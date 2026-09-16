"""Black-box MCP authorization flow against a locally built auth server."""

import asyncio
import os
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mcp_auth_client import (
    AsyncHTTPClient,
    JWTVerifier,
    OAuthState,
    authorization_url,
    discover_authorization_server,
    discover_protected_resource,
    parse_www_authenticate,
)


class _ResourceHandler(BaseHTTPRequestHandler):
    access_token = ""
    resource_url = ""

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/.well-known/oauth-protected-resource":
            self.send_error(404)
            return
        self._json(
            200,
            {
                "resource": self.resource_url + "/mcp",
                "authorization_servers": [os.environ["MCP_AUTH_E2E_ISSUER"]],
                "scopes_supported": ["tools:read"],
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != f"Bearer {self.access_token}":
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                "Bearer resource_metadata="
                f'"{self.resource_url}/.well-known/oauth-protected-resource"',
            )
            self.end_headers()
            return
        self._json(200, {"jsonrpc": "2.0", "result": {"ok": True}})

    def _json(self, status: int, payload: object) -> None:
        import json

        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_ready(process: subprocess.Popen[bytes], base_url: str) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError("authorization server exited before becoming ready")
        try:
            response = httpx.get(f"{base_url}/readyz", timeout=0.2)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    raise AssertionError("authorization server did not become ready")


@pytest.mark.e2e
def test_mcp_authorization_code_pkce_and_resource_flow() -> None:
    resource_server = ThreadingHTTPServer(("127.0.0.1", 0), _ResourceHandler)
    resource_url = f"http://127.0.0.1:{resource_server.server_port}"
    _ResourceHandler.resource_url = resource_url
    resource_thread = Thread(target=resource_server.serve_forever, daemon=True)
    resource_thread.start()

    auth_port = _free_port()
    auth_url = f"http://127.0.0.1:{auth_port}"
    os.environ["MCP_AUTH_E2E_ISSUER"] = auth_url
    root = Path(__file__).parents[2]
    binary = os.environ.get("MCP_AUTH_SERVER_BINARY")
    command = [binary] if binary else ["go", "run", "./cmd/auth-server"]
    environment = {
        **os.environ,
        "MCP_AUTH_ISSUER": auth_url,
        "MCP_AUTH_RESOURCE": resource_url + "/mcp",
        "MCP_AUTH_LISTEN_ADDR": f"127.0.0.1:{auth_port}",
        "MCP_AUTH_ALLOWED_SCOPES": "tools:read",
        "MCP_AUTH_LOCAL_DEVELOPMENT": "true",
        "MCP_AUTH_LOCAL_SUBJECT": "e2e-user",
        "MCP_AUTH_REQUIRE_HTTPS": "false",
    }
    process = subprocess.Popen(
        command,
        cwd=root / "auth-server",
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_for_ready(process, auth_url)
        with httpx.Client(follow_redirects=False) as client:
            challenge_response = client.post(resource_url + "/mcp")
            assert challenge_response.status_code == 401
            challenge = parse_www_authenticate(challenge_response.headers["WWW-Authenticate"])
            metadata_url = resource_url + "/.well-known/oauth-protected-resource"
            assert challenge.scheme == "Bearer"
            assert challenge.resource_metadata == metadata_url

            async def discover() -> tuple[object, object]:
                async with AsyncHTTPClient() as async_http:
                    protected = await discover_protected_resource(async_http.client, metadata_url)
                    auth = await discover_authorization_server(
                        async_http.client, protected.authorization_servers[0]
                    )
                    return protected, auth

            protected, auth = asyncio.run(discover())
            assert protected.resource == resource_url + "/mcp"
            client_registration = client.post(
                auth.authorization_endpoint.rsplit("/", 1)[0] + "/register",
                json={
                    "client_name": "local-e2e-client",
                    "redirect_uris": ["http://127.0.0.1:39001/callback"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert client_registration.status_code == 201
            client_id = client_registration.json()["client_id"]

            oauth_state = OAuthState.generate()
            request_url = authorization_url(
                auth.authorization_endpoint,
                client_id,
                "http://127.0.0.1:39001/callback",
                resource_url + "/mcp",
                {"tools:read"},
                oauth_state,
            )
            callback = client.get(request_url + "&approve=true")
            assert callback.status_code == 302
            callback_query = parse_qs(urlsplit(callback.headers["Location"]).query)
            oauth_state.validate_callback(callback_query["state"][0])
            code = callback_query["code"][0]

            token_response = client.post(
                auth.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": "http://127.0.0.1:39001/callback",
                    "code_verifier": oauth_state.code_verifier,
                    "resource": resource_url + "/mcp",
                },
            )
            assert token_response.status_code == 200
            access_token = token_response.json()["access_token"]
            _ResourceHandler.access_token = access_token

            jwks = client.get(auth.jwks_uri).json()
            verifier = JWTVerifier.from_jwks(
                jwks,
                issuer=auth.issuer,
                audience=resource_url + "/mcp",
                required_scopes={"tools:read"},
            )
            claims = asyncio.run(verifier.verify(access_token))
            assert claims.subject == "e2e-user"
            assert "tools:read" in claims.scopes

            mcp_response = client.post(
                resource_url + "/mcp", headers={"Authorization": f"Bearer {access_token}"}
            )
            assert mcp_response.status_code == 200
            assert mcp_response.json()["result"]["ok"] is True
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        resource_server.shutdown()
        resource_server.server_close()
        resource_thread.join(timeout=5)
        os.environ.pop("MCP_AUTH_E2E_ISSUER", None)
