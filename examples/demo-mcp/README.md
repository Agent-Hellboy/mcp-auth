# Demo MCP resource server

In-tree dummy MCP server for Compose end-to-end tests. It has no downstream
cloud SDK. It publishes Protected Resource Metadata, requires a `tools:read`
MCP access token from mcp-auth, and exposes one tool (`whoami`).

The Compose job in this repository runs this server in front of Keycloak. See
[docs/demo-example.md](../../docs/demo-example.md).
