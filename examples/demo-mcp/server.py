"""Minimal MCP resource server used by the Keycloak Compose E2E."""

from __future__ import annotations

import os

from fastmcp import FastMCP
from mcp_auth_client import build_remote_auth, public_base_url

ISSUER = os.environ["MCP_AUTH_ISSUER"]
JWKS_URI = os.environ["MCP_AUTH_JWKS_URI"]
MCP_PATH = os.getenv("MCP_PATH", "/mcp")
PORT = int(os.getenv("MCP_PORT", "6328"))
BASE_URL = public_base_url()

mcp = FastMCP(
    "demo-mcp",
    website_url="https://example.com",
    instructions="Dummy resource server for mcp-auth end-to-end tests.",
    auth=build_remote_auth(
        resource_url=BASE_URL,
        issuer=ISSUER,
        jwks_uri=JWKS_URI,
        scopes_supported=["tools:read"],
        ssrf_safe=os.getenv("MCP_AUTH_JWKS_SSRF_SAFE", "true").strip().lower()
        not in {"0", "false", "no", "off"},
        mcp_path=MCP_PATH,
    ),
)


@mcp.tool
def whoami() -> dict[str, str]:
    """Return a static marker so an authenticated tools/call has a payload."""

    return {"server": "demo-mcp", "ok": "true"}


def main() -> None:
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=PORT,
        path=MCP_PATH,
        stateless_http=True,
    )


if __name__ == "__main__":
    main()
