# Optional Databricks MCP example

This directory is intentionally provider-specific and is not imported by the core packages. Replace the placeholder URL in `.gitmodules` with a public MCP server repository before initializing the optional submodule:

```bash
git submodule update --init --recursive
```

The example contract is:

1. Configure `mcp_auth_client.JWTVerifier` and `RemoteAuthProvider` with the generic authorization server.
2. Require `tools:read` on read-only MCP tools.
3. Use the verified subject claim for per-user identity propagation.
4. If the downstream provider requires it, use `TokenExchangeClient` to obtain a distinct token whose audience is the downstream API.
5. Do not expose write tools or forward the inbound MCP client token.

The example uses only neutral values and no provider SDK is required for core installation or tests. See `.env.example` and [the example guide](../../docs/databricks-example.md).
