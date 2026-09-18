# Examples

`examples/demo-mcp` is a dummy MCP resource server used by the Keycloak
Compose end-to-end job. It depends only on the in-repo Python SDK.

`examples/typescript-mcp` is a protected Node.js MCP JSON-RPC server using the
in-repo TypeScript SDK. It demonstrates resource metadata, bearer challenges,
JWT validation, and exposing the authenticated subject to a tool.

`examples/go-mcp` provides the equivalent dependency-light server using the Go
SDK and the standard library HTTP server.
