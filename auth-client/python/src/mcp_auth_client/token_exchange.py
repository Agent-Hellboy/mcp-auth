import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt

from .cache import BoundedTokenCache


@dataclass(frozen=True, slots=True)
class TokenSet:
    access_token: str
    token_type: str
    expires_at: float
    audience: str
    scopes: frozenset[str]
    refresh_token: str | None = None

    @classmethod
    def from_response(cls, data: dict[str, Any], audience: str) -> "TokenSet":
        token = data.get("access_token")
        if not isinstance(token, str):
            raise ValueError("token response has no access_token")
        expires_in = data.get("expires_in", 300)
        if not isinstance(expires_in, (int, float)) or expires_in <= 0:
            raise ValueError("token response has invalid expires_in")
        return cls(
            token,
            str(data.get("token_type", "Bearer")),
            time.time() + float(expires_in),
            audience,
            frozenset(str(data.get("scope", "")).split()),
            data.get("refresh_token"),
        )


class PrivateKeyJWTClientAuth:
    def __init__(
        self, client_id: str, private_key_pem: str | bytes, key_id: str, audience: str | None = None
    ) -> None:
        self.client_id, self.private_key_pem, self.key_id = client_id, private_key_pem, key_id
        self.audience = audience

    def assertion(self, token_endpoint: str, lifetime: int = 300) -> str:
        now = int(time.time())
        return str(
            jwt.encode(
                {
                    "iss": self.client_id,
                    "sub": self.client_id,
                    "aud": self.audience or token_endpoint,
                    "iat": now,
                    "exp": now + lifetime,
                    "jti": secrets.token_urlsafe(16),
                },
                self.private_key_pem,
                algorithm="RS256",
                headers={"kid": self.key_id, "typ": "JWT"},
            )
        )

    def form_fields(self, token_endpoint: str) -> dict[str, str]:
        return {
            "client_id": self.client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.assertion(token_endpoint),
        }


class TokenExchangeClient:
    def __init__(
        self,
        token_endpoint: str,
        client_auth: PrivateKeyJWTClientAuth | None = None,
        http_client: httpx.AsyncClient | None = None,
        cache: BoundedTokenCache | None = None,
    ) -> None:
        if urlparse(token_endpoint).scheme not in {"https", "http"}:
            raise ValueError("token endpoint must be an absolute URL")
        self.token_endpoint, self.client_auth = token_endpoint, client_auth
        self._http_client, self._owns_client = http_client, http_client is None
        self.cache = cache or BoundedTokenCache()

    async def __aenter__(self) -> "TokenExchangeClient":
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(follow_redirects=False)
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()

    async def exchange(
        self,
        subject_token: str,
        audience: str,
        scopes: set[str] | frozenset[str] = frozenset(),
        use_cache: bool = True,
    ) -> TokenSet:
        key = f"{hash(subject_token)}|{audience}|{' '.join(sorted(scopes))}"
        if use_cache:
            cached = self.cache.get(key)
            if isinstance(cached, TokenSet):
                return cached
        if self._http_client is None:
            raise RuntimeError(
                "TokenExchangeClient must be used as an async context manager or "
                "given an httpx client"
            )
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
            "scope": " ".join(sorted(scopes)),
        }
        if self.client_auth:
            form.update(self.client_auth.form_fields(self.token_endpoint))
        response = await self._http_client.post(self.token_endpoint, data=form)
        response.raise_for_status()
        token = TokenSet.from_response(response.json(), audience)
        if use_cache:
            self.cache.put(key, token, token.expires_at)
        return token
