# Local development

Requirements: Go 1.26+ and Python 3.12+.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
go test ./auth-server/... ./auth-client/go/...
pytest
```

Run the authorization server in local mode. It generates an ephemeral RSA key when no key file is configured; do not use that mode for production.

```bash
MCP_AUTH_LOCAL_DEVELOPMENT=true \
MCP_AUTH_REQUIRE_HTTPS=false \
MCP_AUTH_REGISTRATION_ENABLED=true \
go run ./auth-server/cmd/auth-server
```

The default issuer is `http://localhost:8080`, the resource audience is `http://localhost:8081/mcp`, and metadata is available at `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, and `/.well-known/jwks.json`.

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

CI also runs Compose MCP OAuth compatibility with Keycloak and the in-tree
demo resource server, Go vulnerability analysis, Python dependency auditing, a
Trivy HIGH/CRITICAL scan of the authorization-server image, and the
public-repository secret/artifact audit.

A published GitHub Release runs `.github/workflows/docker-release.yml`, which
builds a multi-arch `auth-server` image and pushes
`princekrroshan01/mcp-auth-server:<version>` (and `latest` when the release is
not a prerelease). The workflow logs in with repository secrets
`DOCKER_USERNAME` and `DOCKER_PASSWORD` (a Docker Hub access token, not an
account password).

The compatibility checks cover the shared authorization flow used by the
2025-06-18 and 2026-07-28 MCP authorization specifications. The server emits
the newer authorization-response `iss` parameter by default; setting
`MCP_AUTH_AUTHORIZATION_RESPONSE_ISS=false` preserves the earlier response
shape for deployments that need it.
