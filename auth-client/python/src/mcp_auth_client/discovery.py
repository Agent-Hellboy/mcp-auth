from urllib.parse import urlparse, urlunparse

import httpx

from .http import json_get
from .models import AuthorizationServerConfig, ProtectedResourceConfig


def _well_known(issuer: str, name: str) -> str:
    """RFC 8414 section 3.1: the well-known segment goes between the host and
    the issuer's path, so https://host/tenant is described at
    https://host/.well-known/<name>/tenant."""
    parsed = urlparse(issuer.rstrip("/"))
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("issuer must be an absolute HTTPS or HTTP URL")
    path = parsed.path.strip("/")
    well_known = f"/.well-known/{name}" + (f"/{path}" if path else "")
    return urlunparse((parsed.scheme, parsed.netloc, well_known, "", "", ""))


def _discovery_candidates(issuer: str) -> list[str]:
    """The metadata URLs to try, in order.

    RFC 8414 first, then the OIDC-style suffix form. The suffix form is not what
    the spec says, but it is what a path-mounted server that predates RFC 8414
    awareness actually serves, and dropping it would strand those deployments.
    An issuer with no path produces the same URLs both ways, so the suffix
    entries collapse into the first two.
    """
    base = issuer.rstrip("/")
    candidates = [
        _well_known(issuer, "oauth-authorization-server"),
        _well_known(issuer, "openid-configuration"),
    ]
    for name in ("oauth-authorization-server", "openid-configuration"):
        suffix = f"{base}/.well-known/{name}"
        if suffix not in candidates:
            candidates.append(suffix)
    return candidates


async def discover_protected_resource(
    client: httpx.AsyncClient, resource_metadata_url: str
) -> ProtectedResourceConfig:
    return ProtectedResourceConfig.from_metadata(await json_get(client, resource_metadata_url))


async def discover_authorization_server(
    client: httpx.AsyncClient, issuer: str
) -> AuthorizationServerConfig:
    last_error: Exception | None = None
    for endpoint in _discovery_candidates(issuer):
        try:
            return AuthorizationServerConfig.from_metadata(await json_get(client, endpoint))
        except Exception as error:  # noqa: BLE001 - retried against the next candidate
            last_error = error
    raise last_error if last_error else RuntimeError("authorization-server discovery failed")
