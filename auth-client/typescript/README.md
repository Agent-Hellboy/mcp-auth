# @mcp-auth/client

Provider-neutral authorization helpers for Node.js MCP resource servers. The
SDK validates audience-bound JWT access tokens, publishes RFC 9728 metadata,
creates standards-compliant bearer challenges, discovers OAuth metadata, and
performs RFC 8693 token exchange.

Requires Node.js 20 or newer.

```bash
npm install @mcp-auth/client
```

Until the package is published, install it from a checkout or use the workspace
path as shown by `examples/typescript-mcp`.

```ts
import { JWTVerifier, authenticateRequest } from "@mcp-auth/client";

const verifier = new JWTVerifier({
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  issuer: "https://auth.example.com",
  audience: "https://mcp.example.com/mcp",
  requiredScopes: ["tools:read"],
});

const claims = await authenticateRequest(request, verifier);
console.log(claims.subject);
```

See [`../../examples/typescript-mcp`](../../examples/typescript-mcp) for a
complete protected MCP server using Node's built-in HTTP server.
