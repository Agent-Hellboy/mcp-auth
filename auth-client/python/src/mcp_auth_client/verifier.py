import json
import time
from dataclasses import dataclass
from typing import Any, cast

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm


class TokenVerificationError(ValueError):
    """Raised for any invalid inbound MCP access token."""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    subject: str
    issuer: str
    audience: str | list[str]
    scopes: frozenset[str]
    claims: dict[str, Any]


class JWTVerifier:
    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str,
        required_scopes: set[str] | frozenset[str] = frozenset(),
        algorithms: tuple[str, ...] = ("RS256",),
        http_client: httpx.AsyncClient | None = None,
        jwks_ttl: float = 300.0,
    ) -> None:
        if not algorithms:
            raise ValueError("at least one JWT algorithm must be allowlisted")
        if any(algorithm not in {"RS256", "RS384", "RS512"} for algorithm in algorithms):
            raise ValueError("only RSA SHA-2 algorithms are supported by the default verifier")
        self.jwks_uri, self.issuer, self.audience = jwks_uri, issuer, audience
        self.required_scopes = frozenset(required_scopes)
        self.algorithms = algorithms
        self._http_client = http_client
        self._jwks_ttl = jwks_ttl
        self._jwks: dict[str, Any] = {}
        self._jwks_loaded_at = 0.0

    @classmethod
    def from_jwks(cls, jwks: dict[str, object], **kwargs: object) -> "JWTVerifier":
        verifier = cls(jwks_uri="in-memory://jwks", **kwargs)  # type: ignore[arg-type]
        verifier._set_jwks(jwks)
        return verifier

    async def verify(self, token: str) -> TokenClaims:
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            kid = header.get("kid")
            if not isinstance(algorithm, str) or algorithm not in self.algorithms:
                raise TokenVerificationError("JWT algorithm is not allowlisted")
            if not isinstance(kid, str):
                raise TokenVerificationError("JWT kid is missing")
            if not self._jwks or time.time() - self._jwks_loaded_at >= self._jwks_ttl:
                await self._load_jwks()
            jwk = self._jwks.get(kid)
            if jwk is None:
                await self._load_jwks(force=True)
                jwk = self._jwks.get(kid)
            if jwk is None:
                raise TokenVerificationError("JWT signing key was not found")
            key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            claims = jwt.decode(
                token,
                key=cast(Any, key),
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
            scopes = frozenset(str(claims.get("scope", "")).split())
            if not self.required_scopes.issubset(scopes):
                raise TokenVerificationError("JWT does not contain all required scopes")
            audience = claims["aud"]
            if not isinstance(audience, (str, list)):
                raise TokenVerificationError("JWT audience has an invalid type")
            return TokenClaims(str(claims["sub"]), str(claims["iss"]), audience, scopes, claims)
        except TokenVerificationError:
            raise
        except (jwt.PyJWTError, TypeError, ValueError, KeyError) as exc:
            raise TokenVerificationError("invalid JWT") from exc

    async def _load_jwks(self, force: bool = False) -> None:
        if not force and self._jwks and time.time() - self._jwks_loaded_at < self._jwks_ttl:
            return
        if self.jwks_uri.startswith("in-memory://"):
            if not self._jwks:
                raise TokenVerificationError("in-memory JWKS was not configured")
            return
        owns_client = self._http_client is None
        client = self._http_client or httpx.AsyncClient()
        try:
            response = await client.get(self.jwks_uri, headers={"Accept": "application/json"})
            response.raise_for_status()
            self._set_jwks(response.json())
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise TokenVerificationError("unable to load JWKS") from exc
        finally:
            if owns_client:
                await client.aclose()

    def _set_jwks(self, data: object) -> None:
        if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
            raise TokenVerificationError("JWKS response is invalid")
        self._jwks = {
            str(item["kid"]): item
            for item in data["keys"]
            if isinstance(item, dict) and isinstance(item.get("kid"), str)
        }
        self._jwks_loaded_at = time.time()
