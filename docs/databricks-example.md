# Optional Databricks example

The Databricks example is optional and intentionally separate from the core. It is represented by the placeholder submodule entry in `.gitmodules`:

```bash
git submodule update --init --recursive
```

Replace the placeholder owner with the public example repository you choose before initialization. The core repository remains installable and testable when the submodule is absent.

## Generic configuration

The example's `.env.example` uses:

- `MCP_AUTH_ISSUER` and `MCP_AUTH_JWKS_URI` for discovery and JWT verification.
- `MCP_RESOURCE_AUDIENCE` for audience validation.
- `MCP_REQUIRED_SCOPES=tools:read` for read-only tools.
- `DOWNSTREAM_TOKEN_ENDPOINT` and `DOWNSTREAM_AUDIENCE` for optional exchange.

No real URLs, workspace identifiers, credentials, private keys, or deployment values belong in the example.

## Policy

The example should expose read-only data tools, require `tools:read`, and derive per-user identity from the verified `sub` claim. A downstream API call must use a separate token minted for the downstream audience through `TokenExchangeClient` or a provider adapter. The inbound MCP client token must never be sent to that API.
