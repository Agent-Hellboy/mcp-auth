"""Serve the RFC 9728 protected resource metadata document.

``scopes_supported`` is the catalogue of scopes the resource offers. ``required_scopes``
on the verifier is the gate for calling the resource at all. They default to the
same set, so a server that only has one scope cannot advertise a different one by
accident. Pass ``scopes_supported`` explicitly when the catalogue is wider than
the gate, which is what per-tool scope checks need.
"""

from collections.abc import Sequence

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
    scopes_supported: Sequence[str] | None = None,
) -> dict[str, object]:
    """Build the document a resource server serves at
    ``/.well-known/oauth-protected-resource[/<path>]``.

    When ``scopes_supported`` is omitted it is derived from the verifier's
    required scopes. Pass it explicitly to advertise a wider catalogue than the
    gate enforces. The member is omitted when the resulting list is empty, as
    RFC 9728 prefers over an empty list.

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
    if scopes_supported is None:
        scopes = required_scopes(verifier)
    else:
        scopes = sorted(set(scopes_supported))
    if scopes:
        document["scopes_supported"] = scopes
    return document
