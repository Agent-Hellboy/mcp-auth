import re
from dataclasses import dataclass

from .verifier import InsufficientScopeError, JWTVerifier, TokenClaims, TokenVerificationError


@dataclass(frozen=True, slots=True)
class ProtectedResourceChallenge:
    scheme: str
    resource_metadata: str | None
    scope: str | None


def parse_www_authenticate(value: str) -> ProtectedResourceChallenge:
    if not value:
        raise ValueError("empty WWW-Authenticate header")
    scheme, _, parameters = value.partition(" ")
    match = re.search(r'resource_metadata="([^"]+)"', parameters)
    scope = re.search(r'scope="([^"]+)"', parameters)
    return ProtectedResourceChallenge(
        scheme=scheme,
        resource_metadata=match.group(1) if match else None,
        scope=scope.group(1) if scope else None,
    )


def unauthorized_headers(
    resource_metadata_url: str, scopes: set[str] | frozenset[str] | None = None
) -> dict[str, str]:
    """Build the WWW-Authenticate challenge for a 401.

    RFC 9110 section 11.6.1 separates auth-params with commas; omitting the
    comma produces a header that lenient clients accept and strict ones reject.
    """

    challenge = f'Bearer resource_metadata="{resource_metadata_url}"'
    if scopes:
        challenge += f', scope="{" ".join(sorted(scopes))}"'
    return {"WWW-Authenticate": challenge}


def unauthorized_headers_for_error(
    resource_metadata_url: str,
    scopes: set[str] | frozenset[str] | None = None,
    error: str = "",
    description: str = "",
) -> dict[str, str]:
    """Build a challenge that names the failure, per RFC 6750 section 3.

    A 403 without error="insufficient_scope" tells the client only that it was
    refused, not that a larger scope would succeed, so it cannot retry. Pair
    this with scopes_supported in the resource metadata: the challenge says a
    scope is missing, the metadata says which one.
    """

    challenge = unauthorized_headers(resource_metadata_url, scopes)["WWW-Authenticate"]
    if error:
        challenge += f', error="{error}"'
    if description:
        challenge += f', error_description="{description}"'
    return {"WWW-Authenticate": challenge}


@dataclass(frozen=True, slots=True)
class BearerAuthResult:
    status: int
    headers: dict[str, str]
    claims: TokenClaims | None = None


async def authorize_bearer(
    verifier: JWTVerifier,
    authorization: str | None,
    resource_metadata_url: str,
) -> BearerAuthResult:
    """Decide the HTTP response for one bearer token.

    A missing or invalid token is 401. A token that is valid but missing a
    required scope is 403 ``insufficient_scope`` with a ``scope`` parameter,
    matching ``RequireToken`` in the Go SDK.
    """

    parts = (authorization or "").split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return BearerAuthResult(401, unauthorized_headers(resource_metadata_url))
    try:
        claims = await verifier.verify(parts[1])
    except InsufficientScopeError:
        return BearerAuthResult(
            403,
            unauthorized_headers_for_error(
                resource_metadata_url,
                verifier.required_scopes,
                "insufficient_scope",
                "required scope is missing",
            ),
        )
    except TokenVerificationError:
        return BearerAuthResult(
            401,
            unauthorized_headers_for_error(
                resource_metadata_url, None, "invalid_token", "token is invalid"
            ),
        )
    return BearerAuthResult(200, {}, claims)
