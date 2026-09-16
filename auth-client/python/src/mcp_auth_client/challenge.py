import re
from dataclasses import dataclass


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
    challenge = f'Bearer resource_metadata="{resource_metadata_url}"'
    if scopes:
        challenge += f' scope="{" ".join(sorted(scopes))}"'
    return {"WWW-Authenticate": challenge}
