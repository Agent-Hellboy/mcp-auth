import importlib
import inspect
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
        ssrf_safe: bool = True,
    ) -> None:
        self.token_verifier = token_verifier
        self.authorization_servers = authorization_servers
        self.base_url = base_url
        self.allowed_client_redirect_uris = allowed_client_redirect_uris
        self.scopes_supported = scopes_supported
        self.ssrf_safe = ssrf_safe

    def build(self) -> Any:
        try:
            auth_module = importlib.import_module("fastmcp.server.auth")
            jwt_module = importlib.import_module("fastmcp.server.auth.providers.jwt")
            FastMCPRemoteAuthProvider = auth_module.RemoteAuthProvider
            FastMCPJWTVerifier = jwt_module.JWTVerifier
        except ImportError as exc:
            raise RuntimeError(
                "install mcp-auth-client[fastmcp] to build the FastMCP adapter"
            ) from exc
        verifier_kwargs: dict[str, Any] = {
            "jwks_uri": self.token_verifier.jwks_uri,
            "issuer": self.token_verifier.issuer,
            "audience": self.token_verifier.audience,
        }
        if "ssrf_safe" in inspect.signature(FastMCPJWTVerifier).parameters:
            verifier_kwargs["ssrf_safe"] = self.ssrf_safe
        if "required_scopes" in inspect.signature(FastMCPJWTVerifier).parameters:
            verifier_kwargs["required_scopes"] = sorted(self.token_verifier.required_scopes)
        verifier = FastMCPJWTVerifier(**verifier_kwargs)
        kwargs: dict[str, Any] = {
            "token_verifier": verifier,
            "authorization_servers": self.authorization_servers,
            "base_url": self.base_url,
        }
        provider_signature = inspect.signature(FastMCPRemoteAuthProvider)
        if self.allowed_client_redirect_uris is not None:
            kwargs["allowed_client_redirect_uris"] = self.allowed_client_redirect_uris
        if (
            self.scopes_supported is not None
            and "scopes_supported" in provider_signature.parameters
        ):
            kwargs["scopes_supported"] = self.scopes_supported
        return FastMCPRemoteAuthProvider(**kwargs)
