"""The resource server's advertised scopes must match the scopes it enforces."""

import pytest
from mcp_auth_client import (
    protected_resource_metadata,
    required_scopes,
    unauthorized_headers,
    unauthorized_headers_for_error,
)
from mcp_auth_client.verifier import JWTVerifier

RESOURCE = "https://mcp.example.com/ping/mcp"
ISSUER = "https://auth.example.com/mcp-auth"


def verifier(*scopes: str) -> JWTVerifier:
    return JWTVerifier(
        jwks_uri="https://auth.example.com/jwks",
        issuer=ISSUER,
        audience=RESOURCE,
        required_scopes=set(scopes),
    )


def test_metadata_advertises_required_scopes_sorted():
    document = protected_resource_metadata(verifier("tools:write", "tools:read"), RESOURCE, ISSUER)

    assert document["resource"] == RESOURCE
    assert document["authorization_servers"] == [ISSUER]
    assert document["bearer_methods_supported"] == ["header"]
    # Sorted, so the document is byte-identical between requests.
    assert document["scopes_supported"] == ["tools:read", "tools:write"]


@pytest.mark.parametrize("subject", [None, verifier()])
def test_metadata_omits_scopes_when_none_are_required(subject):
    # RFC 9728 prefers omitting the member over publishing an empty list.
    assert "scopes_supported" not in protected_resource_metadata(subject, RESOURCE, ISSUER)


def test_advertised_scopes_match_enforced_scopes():
    guard = verifier("tools:read")
    document = protected_resource_metadata(guard, RESOURCE, ISSUER)

    assert document["scopes_supported"] == required_scopes(guard)
    assert set(document["scopes_supported"]) == set(guard.required_scopes)


def test_challenge_separates_auth_params_with_commas():
    # RFC 9110 section 11.6.1. Without the comma, strict parsers reject the header.
    header = unauthorized_headers("https://mcp.example.com/.well-known/x", {"tools:read"})
    assert header["WWW-Authenticate"] == (
        'Bearer resource_metadata="https://mcp.example.com/.well-known/x", scope="tools:read"'
    )


def test_error_challenge_names_the_failure_and_the_scope():
    # This is what lets a client retry with a larger scope instead of giving up.
    header = unauthorized_headers_for_error(
        "https://mcp.example.com/.well-known/x",
        {"tools:read"},
        "insufficient_scope",
        "required scope is missing",
    )["WWW-Authenticate"]

    assert 'error="insufficient_scope"' in header
    assert 'scope="tools:read"' in header
    assert 'error_description="required scope is missing"' in header
    assert header.count(", ") == 3
