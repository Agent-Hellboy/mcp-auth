from urllib.parse import urlparse

import httpx

from .http import json_get
from .models import AuthorizationServerConfig, ProtectedResourceConfig


def _well_known(issuer: str) -> str:
    parsed = urlparse(issuer.rstrip("/"))
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("issuer must be an absolute HTTPS or HTTP URL")
    return f"{issuer.rstrip('/')}/.well-known/oauth-authorization-server"


async def discover_protected_resource(
    client: httpx.AsyncClient, resource_metadata_url: str
) -> ProtectedResourceConfig:
    return ProtectedResourceConfig.from_metadata(await json_get(client, resource_metadata_url))


async def discover_authorization_server(
    client: httpx.AsyncClient, issuer: str
) -> AuthorizationServerConfig:
    return AuthorizationServerConfig.from_metadata(await json_get(client, _well_known(issuer)))
