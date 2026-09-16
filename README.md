# mcp-auth

`mcp-auth` is a provider-neutral OAuth platform for HTTP-based Model Context Protocol (MCP) resource servers.

Provider-neutral means both halves of that: an OIDC provider (a connector requesting the `openid` scope, whose
ID token is verified) and a plain OAuth 2.0 one (no `openid`, identity read from `userinfo_endpoint`) are both
usable, signing with RS256, PS256, or ES256, with endpoints either configured directly or discovered from the
issuer. See [OIDC or plain OAuth 2.0](docs/auth-server.md#oidc-or-plain-oauth-20).

The repository contains:

- `auth-server/`: a standalone Go OAuth authorization server.
- `auth-client/python/`: a reusable Python resource-server SDK, including a FastMCP adapter.
- `auth-client/go/`: a reusable Go resource-server SDK.
- `examples/databricks-mcp/`: an optional Git submodule containing the provider-specific example; the core does not depend on it.
- `examples/databricks-mcp-integration/`: provider-neutral configuration guidance used by the core tests.

MCP authorization is optional at the protocol level. A particular resource server may still require authorization when it exposes private data or actions.

## Architecture

An MCP client discovers protected-resource metadata from the resource server, discovers the authorization server, completes OAuth Authorization Code + PKCE, and sends an access token to the MCP resource server. The resource server validates the token locally using the authorization server's JWKS. A downstream API receives a separate token obtained through an explicit connector or token exchange; the MCP client token is never forwarded as a downstream credential.

## Packages

Python resource servers can use:

```python
from mcp_auth_client import JWTVerifier, RemoteAuthProvider, TokenExchangeClient

verifier = JWTVerifier(
    jwks_uri="https://auth.example.com/.well-known/jwks.json",
    issuer="https://auth.example.com",
    audience="https://mcp.example.com",
    required_scopes={"tools:read"},
)
```

Go resource servers can import the module under `auth-client/go` and use `mcpauth.JWTVerifier`, discovery helpers, and `TokenExchangeClient`.

The Python SDK is currently installed directly from Git while its API settles:

```bash
python -m pip install "mcp-auth-client @ git+https://github.com/Agent-Hellboy/mcp-auth.git#subdirectory=auth-client/python"
```

The authorization server selects a provider-neutral connector at runtime with
`MCP_AUTH_CONNECTORS_FILE` and `MCP_AUTH_CONNECTOR`; the connector contains
endpoints and environment-variable names for secrets, never secret values.

## Security model

- Authorization Code + PKCE (`S256`) is required for public clients.
- The token-exchange grant requires the caller to authenticate as a pre-registered
  resource server (RFC 7523 `private_key_jwt`) and presents only a `subject_token`
  this server itself issued; it is not an open relay to the upstream connector.
- Access tokens are short-lived JWTs with issuer, audience/resource, scopes, and unique IDs.
- Refresh tokens are opaque, hashed at rest, rotated on use, and revoked on reuse.
- OAuth state and credentials are abstracted behind persistence/key-provider interfaces; enterprise deployments should use shared durable storage plus a secret manager/KMS/HSM, not an unencrypted Docker volume. SQLite is suitable for a single auth-server instance; use a shared database adapter for multiple replicas.
- JWT verifiers allowlist algorithms and validate issuer, audience, expiry, and required scopes.
- Tokens are redacted from structured audit logs.
- Production deployments must use HTTPS, a persistent key provider, durable storage, restrictive CORS/trusted origins, and an upstream identity provider connector appropriate to the deployment.

## Optional example submodule

The example does not participate in core installation or tests. Initialize the public submodule with:

```bash
git submodule update --init --recursive
```

See [docs/databricks-example.md](docs/databricks-example.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Authorization server](docs/auth-server.md)
- [Auth client SDKs](docs/auth-client.md)
- [Optional example](docs/databricks-example.md)
- [Local development](docs/development.md)

## Contributors

- Prince Roshan

## License

MIT. See [LICENSE](LICENSE).
