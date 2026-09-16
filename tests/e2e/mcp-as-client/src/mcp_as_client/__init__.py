"""Small E2E compatibility adapter for the Databricks example's SDK boundary."""

from dataclasses import dataclass

from mcp_auth_client import (
    JWTVerifier,
    PrivateKeyJWTClientAuth,
    RemoteAuthProvider,
)
from mcp_auth_client import (
    TokenExchangeClient as SDKTokenExchangeClient,
)


class TokenExchangeError(RuntimeError):
    """Raised when the configured downstream exchange cannot complete."""


@dataclass(frozen=True, slots=True)
class ExchangedToken:
    access_token: str


class TokenExchangeClient:
    def __init__(self, client: SDKTokenExchangeClient, audience: str) -> None:
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
            raise TokenExchangeError("downstream token exchange failed") from exc
        return ExchangedToken(token.access_token)

    async def aclose(self) -> None:
        if self._entered:
            await self._client.__aexit__(None, None, None)
            self._entered = False


def build_exchange_client(
    token_endpoint: str,
    audience: str,
    client_id: str,
    private_key: bytes,
    key_id: str,
) -> TokenExchangeClient:
    client_auth = PrivateKeyJWTClientAuth(client_id, private_key, key_id)
    client = SDKTokenExchangeClient(token_endpoint, client_auth=client_auth)
    return TokenExchangeClient(client, audience)


def build_remote_auth(
    resource_url: str,
    issuer: str,
    jwks_uri: str,
    scopes_supported: list[str],
    ssrf_safe: bool = True,
) -> object:
    del ssrf_safe
    verifier = JWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=resource_url.rstrip("/") + "/mcp",
    )
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[issuer],
        base_url=resource_url,
        scopes_supported=scopes_supported,
    ).build()


def public_base_url(env_keys: tuple[str, ...]) -> str:
    import os

    for key in env_keys:
        value = os.getenv(key, "").strip().rstrip("/")
        if value:
            return value
    raise ValueError(f"one of {', '.join(env_keys)} is required")


__all__ = [
    "ExchangedToken",
    "JWTVerifier",
    "TokenExchangeClient",
    "TokenExchangeError",
    "build_exchange_client",
    "build_remote_auth",
    "public_base_url",
]
