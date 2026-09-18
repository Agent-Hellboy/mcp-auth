"""Serve the RFC 9728 protected resource metadata document.

A resource server that enforces a required scope but publishes a document
without ``scopes_supported`` leaves the client no way to learn what to ask for.
The client requests no scope, the token carries none, and every call fails 403
insufficient_scope — a failure that reads as broken authentication rather than a
missing advertisement. Deriving the document from the verifier makes that
mistake unrepresentable.
"""

from .verifier import JWTVerifier

__all__ = ["protected_resource_metadata", "required_scopes"]


def required_scopes(verifier: JWTVerifier | None) -> list[str]:
    """Return the verifier's required scopes, sorted so the document is stable."""

    if verifier is None:
        return []
    return sorted(getattr(verifier, "required_scopes", frozenset()))


def protected_resource_metadata(
    verifier: JWTVerifier | None,
    resource: str,
    issuer: str,
) -> dict[str, object]:
    """Build the document a resource server serves at
    ``/.well-known/oauth-protected-resource[/<path>]``.

    ``scopes_supported`` comes from the verifier that guards the resource, so
    the advertised set cannot drift from the enforced one. It is omitted when no
    scope is required, as RFC 9728 prefers over an empty list.

    Mount the result on both the bare well-known path and, for a path-mounted
    resource, the path-suffixed form, because clients derive the URL from the
    resource URI::

        document = protected_resource_metadata(verifier, resource, issuer)
        app.add_route("/.well-known/oauth-protected-resource", handler)
        app.add_route(f"/.well-known/oauth-protected-resource{mcp_path}", handler)
    """

    document: dict[str, object] = {
        "resource": resource,
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    }
    scopes = required_scopes(verifier)
    if scopes:
        document["scopes_supported"] = scopes
    return document
