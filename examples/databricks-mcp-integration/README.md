# Provider integration fixture

This directory contains provider-neutral configuration guidance for an
optional Databricks MCP example. It is not imported by the core packages and
does not require a provider SDK.

The integration should:

1. Configure `mcp_auth_client.JWTVerifier` and `RemoteAuthProvider` with the
   generic authorization server.
2. Require `tools:read` on read-only MCP tools.
3. Use the verified subject claim for per-user identity propagation.
4. Use `TokenExchangeClient` when a downstream API requires a distinct token
   with its own audience.
5. Never forward the inbound MCP client token to a downstream API.

See `.env.example` for neutral placeholders and
[`docs/databricks-example.md`](../../docs/databricks-example.md) for the
optional submodule workflow.
