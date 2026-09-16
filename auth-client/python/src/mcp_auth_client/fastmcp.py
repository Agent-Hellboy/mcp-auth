from typing import Any

from .verifier import JWTVerifier


class RemoteAuthProvider:
    """Adapter that composes this SDK's configuration with FastMCP's provider.

    FastMCP remains an optional dependency. Resource servers that do not use FastMCP
    can use ``JWTVerifier`` and ``unauthorized_headers`` directly.
    """

    def __init__(
        self,
        token_verifier: JWTVerifier,
        authorization_servers: list[str],
        base_url: str,
        allowed_client_redirect_uris: list[str] | None = None,
        scopes_supported: list[str] | None = None,
    ) -> None:
        self.token_verifier = token_verifier
        self.authorization_servers = authorization_servers
        self.base_url = base_url
        self.allowed_client_redirect_uris = allowed_client_redirect_uris
        self.scopes_supported = scopes_supported

    def build(self) -> Any:
        try:
            from fastmcp.server.auth import (  # type: ignore[import-not-found]
                RemoteAuthProvider as FastMCPRemoteAuthProvider,
            )
            from fastmcp.server.auth.providers.jwt import (  # type: ignore[import-not-found]
                JWTVerifier as FastMCPJWTVerifier,
            )
        except ImportError as exc:
            raise RuntimeError(
                "install mcp-auth-client[fastmcp] to build the FastMCP adapter"
            ) from exc
        verifier = FastMCPJWTVerifier(
            jwks_uri=self.token_verifier.jwks_uri,
            issuer=self.token_verifier.issuer,
            audience=self.token_verifier.audience,
        )
        kwargs: dict[str, Any] = {
            "token_verifier": verifier,
            "authorization_servers": self.authorization_servers,
            "base_url": self.base_url,
        }
        if self.allowed_client_redirect_uris is not None:
            kwargs["allowed_client_redirect_uris"] = self.allowed_client_redirect_uris
        if self.scopes_supported is not None:
            kwargs["scopes_supported"] = self.scopes_supported
        return FastMCPRemoteAuthProvider(**kwargs)
