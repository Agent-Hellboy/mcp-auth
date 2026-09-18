# TypeScript MCP resource server

A minimal protected MCP JSON-RPC server using `@mcp-auth/client`. It publishes
RFC 9728 metadata, returns bearer challenges, validates MCP access tokens, and
exposes a `whoami` tool.

```bash
cd examples/typescript-mcp
npm install
npm start
```

The defaults expect the local-development authorization server on port 8080
and serve the MCP endpoint at `http://localhost:8081/mcp`. Override
`MCP_AUTH_ISSUER`, `MCP_AUTH_JWKS_URI`, `MCP_RESOURCE`, or `MCP_PORT` as needed.
