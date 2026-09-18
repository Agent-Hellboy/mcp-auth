# Go MCP resource server

A minimal protected MCP JSON-RPC server using the in-repository Go SDK. It
publishes RFC 9728 metadata, returns bearer challenges, validates MCP access
tokens, and exposes verified subject and scope data to its handler.

```bash
cd examples/go-mcp
GOWORK=off go run .
```

The defaults expect the local-development authorization server on port 8080
and serve `http://localhost:8081/mcp`. Override `MCP_AUTH_ISSUER`,
`MCP_AUTH_JWKS_URI`, `MCP_RESOURCE`, or `MCP_PORT` as needed.
