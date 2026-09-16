# Authorization server

## Run and configure

```bash
go run ./auth-server/cmd/auth-server
```

Copy `.env.example` to a local, untracked `.env` only if useful. The server reads `MCP_AUTH_*` variables; production should inject them through the deployment environment or a secret manager.

Important settings:

- `MCP_AUTH_ISSUER`: stable HTTPS issuer URL, used in metadata and `iss`.
- `MCP_AUTH_RESOURCE`: canonical resource audience placed in `aud`.
- `MCP_AUTH_PRIVATE_KEY_FILE`: PEM RSA key path. Local mode generates an ephemeral test key.
- `MCP_AUTH_STORE`: `memory` for tests/local development or `sqlite` for durable single-node deployments.
- `MCP_AUTH_DATABASE_URL`: SQLite path when `MCP_AUTH_STORE=sqlite`.
- `MCP_AUTH_CONNECTORS_FILE`: JSON file containing named upstream connectors.
- `MCP_AUTH_CONNECTOR`: selected connector name. Local identity/token exchange is available only when
  `MCP_AUTH_LOCAL_DEVELOPMENT=true`; production starts only with a named connector.
- `MCP_AUTH_REGISTRATION_ENABLED`: disable open registration unless policy permits it.
- `MCP_AUTH_ALLOWED_SCOPES`: space-independent comma-separated scope allowlist.
- `MCP_AUTH_TRUSTED_ORIGINS`: exact CORS origins; keep this restrictive.
- `MCP_AUTH_REQUIRE_HTTPS`: enable outside local development.
- `MCP_AUTH_LOCAL_CLIENT_ID`: local-development-only pre-registered client used by
  the Compose token-exchange test; leave it empty outside local development.

The Dockerfile builds a static, non-root image. Put TLS termination in a trusted reverse proxy or serve the endpoints through an HTTPS gateway.

## Metadata and keys

The server publishes:

- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `/.well-known/jwks.json`
- `/healthz` and `/readyz`

The configured RSA key signs RS256 access tokens. For key rotation, deploy a key provider that can publish the current and previous public keys in JWKS, issue tokens with a new `kid`, and remove old keys only after the maximum access-token lifetime plus clock-skew window. The sample server has one configured key slot and should be extended with a durable rotation provider before production.

## Client registration and consent

`POST /register` accepts `client_name`, exact `redirect_uris`, and `token_endpoint_auth_method`. Public clients use `none`; confidential clients may use client-secret authentication. Redirects must be HTTPS or localhost and are matched exactly.

`GET /authorize` requires `response_type=code`, `code_challenge_method=S256`, `code_challenge`, `resource`, and a registered redirect URI. It renders a consent page. In production, accepting consent redirects to the selected connector's upstream authorization endpoint and `/identity/callback` completes the upstream code flow. Local development also supports `approve=true` to exercise the flow without a browser.

Connector files are keyed JSON objects. They contain upstream endpoints, client
IDs, requested scopes, MCP scopes, and `client_secret_env`—the name of an
environment variable, never a literal secret. The same connector can provide
interactive identity and RFC 8693 downstream exchange. All provider-specific
behavior is behind `IdentityProvider` and `TokenExchanger` interfaces.

## Persistence

`MemoryStore` is for local development and tests. `SQLiteStore` persists clients,
consent requests, authorization codes, and refresh-token hashes transactionally
for a single server instance. A multi-replica production deployment must use a
shared managed database adapter implementing `Store`; the HTTP handlers do not
depend on SQLite. Authorization codes and consent state are one-time and
short-lived. Refresh tokens are opaque, hashed, rotated on use, and revoked when
reuse is detected.

The local token exchanger exists only to make the development Compose flow
self-contained. Production must inject a provider-backed `TokenExchanger` that
validates the subject token and obtains a credential for the downstream audience.

Do not use a Docker volume as the authoritative credential/state store for a multi-instance deployment. Volumes are node-local and create failover, backup, encryption, and access-control problems. A volume is acceptable only as a tightly controlled single-node development or explicitly managed single-node deployment choice. The enterprise default is a shared encrypted database for OAuth state and a secret manager/KMS/HSM for signing keys and confidential client credentials. Implement `Store` and `KeyProvider` adapters for the chosen services; the HTTP handlers do not change.

The built-in `LocalKeyProvider` wraps the development PEM loader and ephemeral generated key. Production should replace it with a `KeyProvider` backed by KMS/HSM signing or a secret manager with rotation support. The server never needs to persist raw refresh tokens or client secrets: it stores hashes, and the secret provider owns private key material.

## Production checklist

- Use an HTTPS issuer and canonical resource URI.
- Use a secret-managed persistent signing key and a planned rotation process.
- Replace `MemoryStore` with a transactional durable implementation.
- Integrate a real `IdentityProvider` and define consent/session policy.
- Restrict registration, scopes, CORS, and trusted origins.
- Set short access-token TTLs and monitor refresh-token reuse.
- Keep structured audit logs, with tokens, secrets, codes, keys, and assertions redacted.
- Add rate limits, CSRF protection at the user-login boundary, secure cookies, and reverse-proxy request limits.
- Verify resource audience in every resource server and never pass through inbound tokens downstream.
