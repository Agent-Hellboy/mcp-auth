from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MCPClientToken:
    """Inbound token presented by an MCP client to the resource server."""

    value: str
    audience: str


@dataclass(frozen=True, slots=True)
class ResourceServerCredential:
    """Service credential used by the resource server as its OAuth client."""

    value: str
    audience: str


@dataclass(frozen=True, slots=True)
class DownstreamToken:
    """Token minted for a downstream API; never substitute an MCPClientToken."""

    value: str
    audience: str
    expires_at: float

    def authorization_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.value}"}
