"""Compose E2E client for the MCP authorization discovery and PKCE flow."""

import asyncio
import html
import json
import re
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt as pyjwt
from jwt.algorithms import RSAAlgorithm
from mcp_auth_client import (
    AsyncHTTPClient,
    AuthorizationServerConfig,
    JWTVerifier,
    OAuthState,
    PrivateKeyJWTClientAuth,
    ProtectedResourceConfig,
    TokenExchangeClient,
    authorization_url,
    discover_authorization_server,
    discover_protected_resource,
    parse_www_authenticate,
)

AUTH_URL = "http://mcp-auth:8080"
RESOURCE_URL = "http://mcp-server:6328/mcp"
MCP_URL = "http://mcp-server:6328/mcp"
PRM_URL = "http://mcp-server:6328/.well-known/oauth-protected-resource/mcp"
REDIRECT_URI = "http://127.0.0.1:39001/callback"
KEYCLOAK_URL = "http://keycloak:8080"
KEYCLOAK_ISSUER = f"{KEYCLOAK_URL}/realms/mcp"
KEYCLOAK_USER = "e2e-user"
KEYCLOAK_PASSWORD = "e2e-password"
RESOURCE_AUTH_KEY_DIR = Path("/var/lib/mcp-resource-auth")
INITIALIZE_PARAMS = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "mcp-auth-compose-e2e", "version": "0.1.0"},
}


def complete_upstream_login(client: httpx.Client, start_url: str) -> httpx.Response:
    """Walk Keycloak's login form until mcp-auth receives the identity callback."""

    url = start_url
    for _ in range(16):
        response = client.get(url)
        if response.status_code == 302:
            location = response.headers["Location"]
            if "/identity/callback" in location:
                url = location
                continue
            if "code=" in urlsplit(location).query:
                return SimpleNamespace(status_code=302, headers={"Location": location})
            url = location
            continue
        if response.status_code == 200 and 'name="username"' in response.text:
            match = re.search(r'<form[^>]*action="([^"]+)"', response.text, re.I)
            assert match is not None
            posted = client.post(
                html.unescape(match.group(1)),
                data={"username": KEYCLOAK_USER, "password": KEYCLOAK_PASSWORD},
            )
            if posted.status_code == 302:
                url = posted.headers["Location"]
                continue
            raise AssertionError(f"Keycloak login returned HTTP {posted.status_code}")
        raise AssertionError(f"unexpected upstream HTTP {response.status_code} at {url}")
    raise AssertionError("Keycloak login did not complete")


async def discover() -> tuple[ProtectedResourceConfig, AuthorizationServerConfig]:
    async with AsyncHTTPClient() as async_http:
        protected = await discover_protected_resource(
            async_http.client,
            PRM_URL,
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
                    and client.get(PRM_URL, timeout=0.5).status_code == 200
                ):
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    raise RuntimeError("Compose services did not become ready")


def run_flow(validate_issuer: bool) -> None:
    variant = "2026 issuer validation" if validate_issuer else "2025-compatible client"
    print(f"[e2e] starting {variant}", flush=True)
    protected, authorization_server = asyncio.run(discover())
    print("[e2e] protected-resource metadata and authorization-server discovery passed", flush=True)
    assert protected.resource == RESOURCE_URL
    scopes = set(protected.scopes_supported or ())
    assert not scopes or "tools:read" in scopes
    assert authorization_server.jwks_uri is not None
    assert authorization_server.registration_endpoint is not None
    assert authorization_server.revocation_endpoint is not None
    assert authorization_server.authorization_response_iss_parameter_supported

    with httpx.Client(follow_redirects=False) as client:
        authorization_metadata = client.get(f"{AUTH_URL}/.well-known/oauth-authorization-server")
        authorization_metadata.raise_for_status()
        metadata = authorization_metadata.json()
        assert metadata["issuer"] == AUTH_URL
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert "authorization_code" in metadata["grant_types_supported"]
        print("[e2e] authorization-server metadata passed", flush=True)

        registration = client.post(
            authorization_server.registration_endpoint,
            json={
                "client_name": "compose-e2e-client",
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "none",
            },
        )
        registration.raise_for_status()
        registration_data = registration.json()
        client_id = registration_data["client_id"]
        assert registration_data["token_endpoint_auth_method"] == "none"
        print("[e2e] dynamic client registration passed", flush=True)

        oauth_state = OAuthState.generate()
        request_url = authorization_url(
            authorization_server.authorization_endpoint,
            client_id,
            REDIRECT_URI,
            RESOURCE_URL,
            {"tools:read"},
            oauth_state,
        )
        authorization_query = parse_qs(urlsplit(request_url).query)
        assert authorization_query["code_challenge_method"] == ["S256"]
        assert authorization_query["nonce"]
        assert authorization_query["resource"] == [RESOURCE_URL]

        consent_page = client.get(request_url)
        assert consent_page.status_code == 200
        consent_match = re.search(r'name="consent_id" value="([^"]+)"', consent_page.text)
        assert consent_match is not None
        consent_response = client.post(
            f"{AUTH_URL}/authorize/consent",
            data={"consent_id": consent_match.group(1), "decision": "approve"},
        )
        assert consent_response.status_code == 302
        callback = complete_upstream_login(client, consent_response.headers["Location"])
        assert callback.status_code == 302
        callback_query = parse_qs(urlsplit(callback.headers["Location"]).query)
        oauth_state.validate_callback(
            callback_query["state"][0],
            returned_issuer=callback_query.get("iss", [None])[0],
            expected_issuer=authorization_server.issuer,
            issuer_parameter_supported=validate_issuer,
        )
        assert callback_query["code"][0]
        print(f"[e2e] consent, state, nonce, and {variant} callback passed", flush=True)

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
        token_data = token_response.json()
        access_token = token_data["access_token"]
        refresh_token = token_data["refresh_token"]
        assert token_data["token_type"] == "Bearer"
        assert token_data["scope"] == "tools:read"
        print("[e2e] authorization-code PKCE token exchange passed", flush=True)

        jwks = client.get(authorization_server.jwks_uri).json()
        verifier = JWTVerifier.from_jwks(
            jwks,
            issuer=authorization_server.issuer,
            audience=RESOURCE_URL,
            required_scopes={"tools:read"},
        )
        claims = asyncio.run(verifier.verify(access_token))
        assert claims.subject == KEYCLOAK_USER
        assert "tools:read" in claims.scopes
        print(
            "[e2e] JWKS signature, issuer, audience, expiry, and scope validation passed",
            flush=True,
        )

        async def exchange_downstream_token() -> str:
            # Reuses the same key pair mcp-server authenticates with, since
            # mcp-auth only has one public key registered for
            # "compose-resource-server" (see resource-keygen in
            # docker-compose.e2e.yml). A resource server's private_key_jwt
            # key must be pre-registered with the auth server; it can't be
            # generated ad hoc by whoever calls the token endpoint.
            private_key_pem = RESOURCE_AUTH_KEY_DIR.joinpath("private.pem").read_bytes()
            key_id = RESOURCE_AUTH_KEY_DIR.joinpath("key_id").read_text().strip()
            client_auth = PrivateKeyJWTClientAuth(
                "compose-resource-server", private_key_pem, key_id
            )
            async with TokenExchangeClient(
                f"{AUTH_URL}/token", client_auth=client_auth
            ) as exchange_client:
                exchanged = await exchange_client.exchange(
                    access_token,
                    audience=RESOURCE_URL,
                    scopes={"tools:read"},
                    use_cache=False,
                )
            return exchanged.access_token

        downstream_token = asyncio.run(exchange_downstream_token())
        assert downstream_token != access_token
        downstream_jwks = client.get(f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs").json()
        header = pyjwt.get_unverified_header(downstream_token)
        jwk = next(key for key in downstream_jwks["keys"] if key["kid"] == header["kid"])
        # Keycloak access tokens commonly omit aud and use azp instead.
        downstream_claims = pyjwt.decode(
            downstream_token,
            key=RSAAlgorithm.from_jwk(json.dumps(jwk)),
            algorithms=["RS256"],
            issuer=KEYCLOAK_ISSUER,
            options={"require": ["exp", "iss"], "verify_aud": False},
        )
        identity = str(
            downstream_claims.get("preferred_username") or downstream_claims.get("sub") or ""
        )
        assert identity == KEYCLOAK_USER or downstream_claims.get("azp") == "mcp-auth"
        print(
            "[e2e] private-key JWT authentication and Keycloak upstream session passed",
            flush=True,
        )

        # A resource server can no longer relay a subject_token without
        # authenticating itself: this must be rejected before it ever reaches
        # the upstream token-exchange call.
        unauthenticated_exchange = client.post(
            f"{AUTH_URL}/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": "compose-resource-server",
                "subject_token": access_token,
            },
        )
        assert unauthenticated_exchange.status_code == 401
        assert unauthenticated_exchange.json()["error"] == "invalid_client"
        print("[e2e] unauthenticated token-exchange rejection passed", flush=True)

        private_key_pem = RESOURCE_AUTH_KEY_DIR.joinpath("private.pem").read_bytes()
        key_id = RESOURCE_AUTH_KEY_DIR.joinpath("key_id").read_text().strip()
        missing_subject_assertion = PrivateKeyJWTClientAuth(
            "compose-resource-server", private_key_pem, key_id
        ).assertion(f"{AUTH_URL}/token")
        exchange_failure = client.post(
            f"{AUTH_URL}/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": "compose-resource-server",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": missing_subject_assertion,
            },
        )
        assert exchange_failure.status_code == 400
        print("[e2e] authenticated token-exchange missing subject_token rejected", flush=True)

        refresh_response = client.post(
            f"{AUTH_URL}/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
        )
        refresh_response.raise_for_status()
        rotated_refresh_token = refresh_response.json()["refresh_token"]
        assert rotated_refresh_token != refresh_token
        reuse_response = client.post(
            f"{AUTH_URL}/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
        )
        assert reuse_response.status_code == 400
        print("[e2e] refresh-token rotation and reuse rejection passed", flush=True)

        revoke_response = client.post(
            authorization_server.revocation_endpoint,
            data={"token": rotated_refresh_token},
        )
        assert revoke_response.status_code == 200
        revoked_refresh_response = client.post(
            f"{AUTH_URL}/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": rotated_refresh_token,
            },
        )
        assert revoked_refresh_response.status_code == 400
        print("[e2e] token revocation passed", flush=True)

        invalid_response = client.post(
            MCP_URL,
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": "Bearer invalid",
            },
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": INITIALIZE_PARAMS,
            },
        )
        assert invalid_response.status_code == 401
        print("[e2e] invalid MCP token rejection passed", flush=True)

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
        print("[e2e] protected MCP request and initialize response passed", flush=True)


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
        assert challenge.resource_metadata == PRM_URL
        print(
            "[e2e] unauthenticated MCP request returned the required bearer metadata challenge",
            flush=True,
        )

    run_flow(validate_issuer=False)
    run_flow(validate_issuer=True)
    print("Compose MCP OAuth compatibility E2E passed")


if __name__ == "__main__":
    main()
