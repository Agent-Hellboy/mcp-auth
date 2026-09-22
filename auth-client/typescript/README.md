# @mcp-auth/client

Provider-neutral authorization helpers for Node.js MCP resource servers. The
SDK validates audience-bound JWT access tokens, publishes RFC 9728 metadata,
creates standards-compliant bearer challenges, discovers OAuth metadata, and
performs RFC 8693 token exchange.

Requires Node.js 22 or newer. The package is ESM-only (`"type": "module"` with an `import` export). CommonJS `require()` of this package needs Node's `require(esm)` support, which is Node 22 or later.

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

`JWTVerifier` allows 60 seconds of clock skew by default (`clockSkewSeconds`). JWKS fetches and token exchange time out after 10 seconds unless `timeoutMs` is set. `TokenExchangeClient` posts only to an `https:` endpoint unless `allowInsecure: true`.

`ssrfSafe` (the default) checks the JWKS URL text, not DNS. It blocks non-HTTPS URLs except loopback names, URLs with userinfo, and non-loopback IP literals. A hostname that resolves to a private address is not blocked, because `jwksUri` is operator-configured.

Shared verifier cases live in [`sdk-conformance/`](../../sdk-conformance). Add a case to `cases.json` and run the Python, Go, and TypeScript suites; do not check in a signed JWT or a PEM file.

See [`../../examples/typescript-mcp`](../../examples/typescript-mcp) for a
complete protected MCP server using Node's built-in HTTP server.
