"""Small provider-neutral integration helpers for MCP resource servers."""

import os
from dataclasses import dataclass

from .fastmcp import RemoteAuthProvider
from .token_exchange import PrivateKeyJWTClientAuth, TokenExchangeClient
from .verifier import JWTVerifier


class TokenExchangeError(RuntimeError):
    """Raised when a downstream provider exchange cannot complete."""

    def __init__(
        self, error: str, description: str | None = None, status_code: int | None = None
    ) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        message = error if description is None else f"{error}: {description}"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ExchangedToken:
    access_token: str


class _ExchangeAdapter:
    def __init__(self, client: TokenExchangeClient, audience: str) -> None:
        self._client = client
        self._audience = audience
        self._entered = False

    async def exchange(self, subject_token: str) -> ExchangedToken:
        try:
            if not self._entered:
                await self._client.__aenter__()
                self._entered = True
            token = await self._client.exchange(subject_token, audience=self._audience)
        except Exception as exc:
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            raise TokenExchangeError("downstream_exchange_failed", status_code=status_code) from exc
        return ExchangedToken(token.access_token)

    async def aclose(self) -> None:
        if self._entered:
            await self._client.__aexit__(None, None, None)
            self._entered = False


def build_exchange_client(
    token_endpoint: str,
    audience: str,
    client_id: str,
    private_key: str | bytes,
    key_id: str,
) -> _ExchangeAdapter:
    """Build a lazy RFC 8693 client for a separate downstream audience."""

    auth = PrivateKeyJWTClientAuth(client_id, private_key, key_id)
    return _ExchangeAdapter(TokenExchangeClient(token_endpoint, client_auth=auth), audience)


def scope_policy(
    scopes_supported: list[str] | None,
    required_scopes: set[str] | frozenset[str] | None,
) -> tuple[frozenset[str], list[str] | None]:
    """Split the catalogue (``scopes_supported``) from the gate (``required_scopes``).

    Omitting ``required_scopes`` derives the gate from the catalogue, which keeps
    a single-scope server short to configure. An explicit gate, including an
    empty one, is kept as given so a tool decorator can require one scope from
    a wider catalogue.
    """

    if required_scopes is None:
        enforced = frozenset(scopes_supported or ())
    else:
        enforced = frozenset(required_scopes)
    if scopes_supported is None:
        advertised = sorted(enforced) or None
    else:
        advertised = list(scopes_supported) or None
    return enforced, advertised


def build_remote_auth(
    resource_url: str,
    issuer: str,
    jwks_uri: str,
    scopes_supported: list[str] | None = None,
    ssrf_safe: bool = True,
    mcp_path: str = "/mcp",
    required_scopes: set[str] | frozenset[str] | None = None,
) -> object:
    """Build the optional FastMCP adapter with an explicit JWKS fetch policy.

    mcp_path is where the resource server mounts its MCP endpoint. The
    audience tokens are validated against is the resource URL plus that path,
    so a server that mounts somewhere other than /mcp has to pass the same
    value here or every token it receives fails audience validation.

    ``scopes_supported`` is the RFC 9728 catalogue. ``required_scopes`` is the
    gate. Leave ``required_scopes`` unset to enforce the catalogue. Pass
    ``required_scopes`` explicitly (``set()`` is meaningful) when individual
    tools check a narrower scope.
    """

    enforced, advertised = scope_policy(scopes_supported, required_scopes)
    verifier = JWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=resource_url.rstrip("/") + "/" + mcp_path.strip("/"),
        required_scopes=enforced,
        ssrf_safe=ssrf_safe,
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[issuer],
        base_url=resource_url,
        scopes_supported=advertised,
        ssrf_safe=ssrf_safe,
    ).build()


def public_base_url(env_keys: tuple[str, ...] = ("PUBLIC_BASE_URL", "MCP_SERVER_URL")) -> str:
    """Return a configured public URL, without embedding deployment knowledge."""

    for key in env_keys:
        value = os.getenv(key, "").strip().rstrip("/")
        if value:
            return value
    raise ValueError(f"one of {', '.join(env_keys)} is required")


__all__ = [
    "ExchangedToken",
    "TokenExchangeError",
    "build_exchange_client",
    "build_remote_auth",
    "public_base_url",
]
