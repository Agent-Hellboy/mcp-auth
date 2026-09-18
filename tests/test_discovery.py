"""Authorization-server discovery URL construction and fallback.

RFC 8414 section 3.1 puts the well-known segment between the host and the
issuer's path. The server side of this repo now serves that form, but
deployments that predate it only answer the OIDC-style suffix URL, so the
client tries the spec form first and falls back.
"""

import httpx
import pytest
from mcp_auth_client.discovery import (
    _discovery_candidates,
    _well_known,
    discover_authorization_server,
)


def test_well_known_inserts_segment_before_the_issuer_path():
    assert (
        _well_known("http://localhost:18080/mcp-auth", "oauth-authorization-server")
        == "http://localhost:18080/.well-known/oauth-authorization-server/mcp-auth"
    )


def test_well_known_handles_a_root_mounted_issuer():
    assert (
        _well_known("https://auth.example.com/", "oauth-authorization-server")
        == "https://auth.example.com/.well-known/oauth-authorization-server"
    )


def test_well_known_rejects_a_relative_issuer():
    with pytest.raises(ValueError):
        _well_known("auth.example.com", "oauth-authorization-server")


def test_candidates_prefer_rfc8414_then_fall_back_to_the_suffix_form():
    assert _discovery_candidates("http://localhost:18080/mcp-auth") == [
        "http://localhost:18080/.well-known/oauth-authorization-server/mcp-auth",
        "http://localhost:18080/.well-known/openid-configuration/mcp-auth",
        "http://localhost:18080/mcp-auth/.well-known/oauth-authorization-server",
        "http://localhost:18080/mcp-auth/.well-known/openid-configuration",
    ]


def test_candidates_do_not_repeat_themselves_for_a_root_issuer():
    candidates = _discovery_candidates("https://auth.example.com")
    assert candidates == [
        "https://auth.example.com/.well-known/oauth-authorization-server",
        "https://auth.example.com/.well-known/openid-configuration",
    ]


@pytest.mark.asyncio
async def test_discovery_falls_back_to_the_suffix_form():
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.url.path != "/mcp-auth/.well-known/oauth-authorization-server":
            return httpx.Response(404)
        return httpx.Response(
            200,
            json={
                "issuer": "http://localhost:18080/mcp-auth",
                "authorization_endpoint": "http://localhost:18080/mcp-auth/authorize",
                "token_endpoint": "http://localhost:18080/mcp-auth/token",
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        config = await discover_authorization_server(client, "http://localhost:18080/mcp-auth")

    assert config.issuer == "http://localhost:18080/mcp-auth"
    assert requested[0] == "/.well-known/oauth-authorization-server/mcp-auth"


@pytest.mark.asyncio
async def test_discovery_stops_at_the_rfc8414_url_when_it_answers():
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "issuer": "http://localhost:18080/mcp-auth",
                "authorization_endpoint": "http://localhost:18080/mcp-auth/authorize",
                "token_endpoint": "http://localhost:18080/mcp-auth/token",
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        await discover_authorization_server(client, "http://localhost:18080/mcp-auth")

    assert requested == ["/.well-known/oauth-authorization-server/mcp-auth"]
