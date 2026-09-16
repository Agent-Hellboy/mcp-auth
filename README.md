# mcp-auth

`mcp-auth` is a provider-neutral OAuth platform for HTTP-based Model Context Protocol (MCP) resource servers.

The repository contains:

- `auth-server/`: a standalone Go OAuth authorization server.
- `auth-client/python/`: a reusable Python resource-server SDK, including a FastMCP adapter.
- `auth-client/go/`: a reusable Go resource-server SDK.
- `examples/databricks-mcp/`: an optional Git submodule containing the provider-specific example; the core does not depend on it.
- `examples/databricks-mcp-integration/`: provider-neutral configuration guidance used by the core tests.

MCP authorization is optional at the protocol level. A particular resource server may still require authorization when it exposes private data or actions.

## Architecture

An MCP client discovers protected-resource metadata from the resource server, discovers the authorization server, completes OAuth Authorization Code + PKCE, and sends an access token to the MCP resource server. The resource server validates the token locally using the authorization server's JWKS. A downstream API receives a separate token obtained through an explicit connector or token exchange; the MCP client token is never forwarded as a downstream credential.

## Local setup

Requirements: Go 1.22+ and Python 3.12+.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
go test ./auth-server/... ./auth-client/go/...
pytest
```

Run the authorization server in local mode. It generates an ephemeral RSA key when no key file is configured; do not use that mode for production.

```bash
go run ./auth-server/cmd/auth-server
```

The default issuer is `http://localhost:8080`, the resource audience is `http://localhost:8081/mcp`, and metadata is available at `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, and `/.well-known/jwks.json`.

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

## Development commands

```bash
ruff check .
ruff format --check .
mypy auth-client/python/src
pytest -q
go test ./auth-server/... ./auth-client/go/...
go vet ./auth-server/... ./auth-client/go/...
uv run pip-audit --skip-editable
python -m build
docker compose -f deploy/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from e2e-client
docker compose -f deploy/docker-compose.e2e.yml down --volumes --remove-orphans
```

CI also runs local and three-service Compose MCP OAuth compatibility flows, Go vulnerability analysis, Python dependency auditing, a Trivy HIGH/CRITICAL scan of the authorization-server image, and the public-repository secret/artifact audit.

The compatibility checks cover the shared authorization flow used by the
2025-06-18 and 2026-07-28 MCP authorization specifications. The server emits
the newer authorization-response `iss` parameter by default; setting
`MCP_AUTH_AUTHORIZATION_RESPONSE_ISS=false` preserves the earlier response
shape for deployments that need it.

## Security model

- Authorization Code + PKCE (`S256`) is required for public clients.
- Access tokens are short-lived JWTs with issuer, audience/resource, scopes, and unique IDs.
- Refresh tokens are opaque, hashed at rest, rotated on use, and revoked on reuse.
- OAuth state and credentials are abstracted behind persistence/key-provider interfaces; enterprise deployments should use a shared encrypted database plus a secret manager/KMS/HSM, not an unencrypted Docker volume.
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

## Contributors

- Prince Roshan

## License

MIT. See [LICENSE](LICENSE).
