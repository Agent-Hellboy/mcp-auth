"""Provider-neutral configuration sketch for the optional example."""

import os

from mcp_auth_client import JWTVerifier, RemoteAuthProvider, TokenExchangeClient


def auth_provider() -> RemoteAuthProvider:
    verifier = JWTVerifier(
        jwks_uri=os.environ["MCP_AUTH_JWKS_URI"],
        issuer=os.environ["MCP_AUTH_ISSUER"],
        audience=os.environ["MCP_RESOURCE_AUDIENCE"],
        required_scopes=set(os.getenv("MCP_REQUIRED_SCOPES", "tools:read").split()),
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[os.environ["MCP_AUTH_ISSUER"]],
        base_url=os.environ["MCP_RESOURCE_AUDIENCE"],
        allowed_client_redirect_uris=["http://localhost:*", "http://127.0.0.1:*"],
    )


def downstream_exchange_client() -> TokenExchangeClient | None:
    endpoint = os.getenv("DOWNSTREAM_TOKEN_ENDPOINT")
    return TokenExchangeClient(endpoint) if endpoint else None


READ_ONLY_POLICY = {"allow_write_tools": False, "required_scope": "tools:read"}
