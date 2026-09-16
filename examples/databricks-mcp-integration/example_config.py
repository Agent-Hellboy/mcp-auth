"""Provider-neutral configuration sketch for an MCP resource server."""

from mcp_auth_client import JWTVerifier, RemoteAuthProvider, TokenExchangeClient


def build_authentication() -> tuple[JWTVerifier, RemoteAuthProvider]:
    verifier = JWTVerifier(
        jwks_uri="https://auth.example.com/.well-known/jwks.json",
        issuer="https://auth.example.com",
        audience="https://mcp.example.com",
        required_scopes={"tools:read"},
    )
    provider = RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=["https://auth.example.com"],
        base_url="https://mcp.example.com",
    )
    return verifier, provider


def build_downstream_exchange() -> TokenExchangeClient:
    """Create a separately configured downstream exchange client.

    The inbound MCP access token is supplied to ``exchange`` only as a
    subject token; the returned token must be sent to the downstream audience.
    """

    return TokenExchangeClient("https://api.example.com/oauth/token")
