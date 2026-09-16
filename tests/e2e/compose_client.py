"""Compose E2E client for the MCP authorization discovery and PKCE flow."""

import asyncio
import time
from urllib.parse import parse_qs, urlsplit

import httpx
from mcp_auth_client import (
    AsyncHTTPClient,
    AuthorizationServerConfig,
    JWTVerifier,
    OAuthState,
    ProtectedResourceConfig,
    authorization_url,
    discover_authorization_server,
    discover_protected_resource,
    parse_www_authenticate,
)

AUTH_URL = "http://mcp-auth:8080"
RESOURCE_URL = "http://mcp-server:6328/databricks/mcp"
MCP_URL = "http://mcp-server:6328/mcp"
REDIRECT_URI = "http://127.0.0.1:39001/callback"
INITIALIZE_PARAMS = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "mcp-auth-compose-e2e", "version": "0.1.0"},
}


async def discover() -> tuple[ProtectedResourceConfig, AuthorizationServerConfig]:
    async with AsyncHTTPClient() as async_http:
        protected = await discover_protected_resource(
            async_http.client,
            "http://mcp-server:6328/.well-known/oauth-protected-resource/databricks/mcp",
        )
        authorization_server = await discover_authorization_server(
            async_http.client, protected.authorization_servers[0]
        )
        return protected, authorization_server


def wait_for_services() -> None:
    with httpx.Client() as client:
        for _ in range(120):
            try:
                if (
                    client.get(f"{AUTH_URL}/readyz", timeout=0.5).status_code == 200
                    and client.get(
                        "http://mcp-server:6328/.well-known/oauth-protected-resource/databricks/mcp",
                        timeout=0.5,
                    ).status_code
                    == 200
                ):
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    raise RuntimeError("Compose services did not become ready")


def run_flow(validate_issuer: bool) -> None:
    protected, authorization_server = asyncio.run(discover())
    assert protected.resource == RESOURCE_URL
    assert {"catalog:read", "sql:read"}.issubset(set(protected.scopes_supported or ()))
    assert authorization_server.jwks_uri is not None
    assert authorization_server.registration_endpoint is not None

    with httpx.Client(follow_redirects=False) as client:
        registration = client.post(
            authorization_server.registration_endpoint,
            json={
                "client_name": "compose-e2e-client",
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "none",
            },
        )
        registration.raise_for_status()
        client_id = registration.json()["client_id"]

        oauth_state = OAuthState.generate()
        request_url = authorization_url(
            authorization_server.authorization_endpoint,
            client_id,
            REDIRECT_URI,
            RESOURCE_URL,
            {"tools:read"},
            oauth_state,
        )
        callback = client.get(request_url + "&approve=true")
        assert callback.status_code == 302
        callback_query = parse_qs(urlsplit(callback.headers["Location"]).query)
        oauth_state.validate_callback(
            callback_query["state"][0],
            returned_issuer=callback_query.get("iss", [None])[0],
            expected_issuer=authorization_server.issuer,
            issuer_parameter_supported=validate_issuer,
        )

        token_response = client.post(
            authorization_server.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": callback_query["code"][0],
                "redirect_uri": REDIRECT_URI,
                "code_verifier": oauth_state.code_verifier,
                "resource": RESOURCE_URL,
            },
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]

        jwks = client.get(authorization_server.jwks_uri).json()
        verifier = JWTVerifier.from_jwks(
            jwks,
            issuer=authorization_server.issuer,
            audience=RESOURCE_URL,
            required_scopes={"tools:read"},
        )
        claims = asyncio.run(verifier.verify(access_token))
        assert claims.subject == "local-user"
        assert "tools:read" in claims.scopes

        mcp_response = client.post(
            MCP_URL,
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": INITIALIZE_PARAMS,
            },
        )
        mcp_response.raise_for_status()
        assert mcp_response.status_code == 200
        assert "serverInfo" in mcp_response.text or "protocolVersion" in mcp_response.text


def main() -> None:
    wait_for_services()
    with httpx.Client() as client:
        challenge_response = client.post(
            MCP_URL,
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": INITIALIZE_PARAMS,
            },
        )
        assert challenge_response.status_code in {401, 403}
        challenge = parse_www_authenticate(challenge_response.headers["WWW-Authenticate"])
        assert challenge.resource_metadata == (
            "http://mcp-server:6328/.well-known/oauth-protected-resource/databricks/mcp"
        )

    run_flow(validate_issuer=False)
    run_flow(validate_issuer=True)
    print("Compose MCP OAuth compatibility E2E passed")


if __name__ == "__main__":
    main()
