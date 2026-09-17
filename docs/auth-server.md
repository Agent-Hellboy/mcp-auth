# Authorization server

The Go authorization server presents standard OAuth endpoints to MCP clients and
adapts a selected upstream OIDC or OAuth 2.0 provider at runtime. One process is
bound to one connector and one MCP resource audience.

```mermaid
flowchart LR
    client["MCP client"]

    subgraph server["auth-server process"]
        endpoints["OAuth endpoints<br/>register, authorize, token, revoke"]
        connector["Selected connector"]
        identity["IdentityProvider"]
        exchange["TokenExchanger"]
        store[("Store")]
        keys["KeyProvider"]

        endpoints --> connector
        connector --> identity
        connector --> exchange
        endpoints --> store
        endpoints --> keys
    end

    idp["Upstream OIDC / OAuth 2.0 provider"]
    resource["MCP resource server"]

    client <-->|"Authorization Code + PKCE"| endpoints
    identity <-->|"Login, ID token, or userinfo"| idp
    exchange <-->|"Access / refresh token"| idp
    endpoints -->|"MCP JWT"| client
    resource -.->|"JWKS and authenticated exchange"| endpoints
```

## Run and configure

```bash
go run ./auth-server/cmd/auth-server
```

Release tags are also published to Docker Hub as
`princekrroshan01/mcp-auth-server:<tag>`:

```bash
docker pull princekrroshan01/mcp-auth-server:latest
```

Copy `.env.example` to a local, untracked `.env` only if useful. The server reads `MCP_AUTH_*` variables; production should inject them through the deployment environment or a secret manager.

Important settings:

- `MCP_AUTH_ISSUER`: stable HTTPS issuer URL, used in metadata and `iss`. A trailing slash is stripped at
  startup; every endpoint the server builds or advertises (`/authorize`, `/token`, `/register`, `/revoke`,
  `/.well-known/jwks.json`, `/identity/callback`) is derived from the normalized value via one method each
  on `Config` — never by concatenating `Issuer` at the point of use — so the advertised endpoint and the one
  actually checked against can't independently drift the way they did before this existed.
- `MCP_AUTH_LOG_LEVEL`: `info` (default) logs one line per request — method, path, status, duration, and
  `client_id` where the request carries one — so a failed connection attempt can be diagnosed from the log
  alone. Set to `silent` to disable it for a deployment that wants quieter logs. This is separate from the
  structured OAuth event audit log, which always runs and always redacts tokens/secrets/codes/keys/assertions.
- `MCP_AUTH_RESOURCE`: canonical resource audience placed in `aud`.
- `MCP_AUTH_RESOURCES`: comma-separated resource allow-list placed in `aud`; use this for multi-resource deployments.
- `MCP_AUTH_RESOURCE`: legacy single-resource setting, retained for compatibility when `MCP_AUTH_RESOURCES` is unset.
- `MCP_AUTH_PRIVATE_KEY_FILE`: PEM RSA key path. Local mode generates an ephemeral test key.
- `MCP_AUTH_STORE`: `memory` for tests/local development or `sqlite` for durable single-node deployments.
- `MCP_AUTH_DATABASE_URL`: SQLite path when `MCP_AUTH_STORE=sqlite`.
- `MCP_AUTH_CONNECTORS_FILE`: JSON file containing named upstream connectors.
- `MCP_AUTH_CONNECTOR`: selected connector name. One running process serves exactly one connector and one
  `MCP_AUTH_RESOURCE`, by design — see [Serving multiple resources](#serving-multiple-resources) below for
  more than one. Any other connector in the file is inert, and is named in a startup warning so it can't be
  mistaken for live. Local identity/token exchange is available only when `MCP_AUTH_LOCAL_DEVELOPMENT=true`;
  production starts only with a named connector.
- `MCP_AUTH_REGISTRATION_ENABLED`: disable open registration unless policy permits it. Defaults to
  `false`, but Cursor and Claude both perform dynamic client registration (`POST /register`) before
  their first connection, with no fallback to a pre-registered client. A real deployment serving
  either of them must set this to `true`, or the first connection attempt fails with no obvious
  cause pointing back to this setting. Combine it with `AllowedClientRedirectURIs` (below) rather
  than leaving registration fully open if the deployment can enumerate its expected clients.
- `MCP_AUTH_ALLOWED_SCOPES`: space-independent comma-separated scope allowlist.
- `MCP_AUTH_TRUSTED_ORIGINS`: exact CORS origins; keep this restrictive.
- `MCP_AUTH_REQUIRE_HTTPS`: enable outside local development. With a plain-HTTP `MCP_AUTH_ISSUER`,
  the upstream redirect_uri this server registers becomes `http://.../identity/callback`, which most
  providers (including Databricks) reject for anything other than `localhost`/`127.0.0.1`. An
  HTTP issuer only works for local development or behind an SSH tunnel to loopback.
- `MCP_AUTH_LOCAL_CLIENT_ID`: local-development-only pre-registered client used by
  the Compose token-exchange test; leave it empty outside local development.
- `MCP_AUTH_RESOURCE_CLIENTS_FILE`: JSON array of resource servers pre-provisioned to
  authenticate the token-exchange grant with RFC 7523 `private_key_jwt`. Each entry
  is `{"client_id", "name", "public_key_pem"}` or `{"client_id", "name", "public_key_file"}`
  (exactly one of the last two), plus an optional `"algorithm"` (`RS256` default, or
  `PS256`/`ES256` — must match the key's own type). A resource server's own private
  key never appears here; only its public key is registered, so the auth server can
  verify the `client_assertion` it presents on every token-exchange request, signed
  with exactly the algorithm it registered — not any algorithm this server happens
  to support, so a client can't switch algorithms without re-registering its key.

The Dockerfile builds a static, non-root image. Put TLS termination in a trusted reverse proxy or serve the endpoints through an HTTPS gateway.

## Metadata and keys

The server publishes:

- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `/.well-known/jwks.json`
- `/healthz` and `/readyz`

The configured RSA key signs RS256 access tokens. For key rotation, deploy a key provider that can publish the current and previous public keys in JWKS, issue tokens with a new `kid`, and remove old keys only after the maximum access-token lifetime plus clock-skew window. The sample server has one configured key slot and should be extended with a durable rotation provider before production.

## Client registration and consent

`POST /register` accepts `client_name`, exact `redirect_uris`, and `token_endpoint_auth_method`. Public clients use `none`; confidential clients may use client-secret authentication. Redirect URIs are matched exactly, and must take one of the shapes RFC 8252 (*OAuth 2.0 for Native Apps*) defines, since that is the profile MCP desktop clients follow:

- `https://` with a host — for example `https://claude.ai/api/mcp/auth_callback`.
- `http://` **only** on loopback: `127.0.0.1`, `[::1]`, or `localhost`. RFC 8252
  §7.3 requires both address families, because a client binding a loopback
  listener cannot know which one the OS will give it.
- A private-use URI scheme (RFC 8252 §7.1) — `claude://oauth/callback`,
  `cursor://…`, `com.example.app:/oauth/callback`. These have no meaningful
  authority component, so no host is required.

Plaintext `http://` to any non-loopback host is rejected. Admitting private-use
schemes broadly is safe because PKCE `S256` is mandatory and `/authorize`
matches the registered `redirect_uri` exactly; a deployment that wants to
restrict which clients may register sets the connector's
`allowed_client_redirect_uris`, which `/register` enforces when non-empty.

`GET /authorize` requires `response_type=code`, `code_challenge_method=S256`, `code_challenge`, a resource from the configured allow-list, and a registered redirect URI. With one configured resource, `resource` may be omitted and defaults to it. It renders a consent page. In production, accepting consent redirects to the selected connector's upstream authorization endpoint and `/identity/callback` completes the upstream code flow. Local development also supports `approve=true` to exercise the flow without a browser.

Connector files are keyed JSON objects. They contain upstream endpoints, client
IDs, requested scopes, MCP scopes, and `client_secret_env`—the name of an
environment variable, never a literal secret. `client_id` can likewise be
supplied indirectly as `client_id_env`; set exactly one of the two. All
provider-specific behavior is behind `IdentityProvider` and `TokenExchanger`
interfaces.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Client as MCP client
    participant AS as auth-server
    participant IdP as Upstream provider
    participant Store

    Client->>AS: /authorize + PKCE challenge + resource
    AS->>Store: Persist one-time consent state and nonce
    AS-->>User: Consent page
    User->>AS: Approve
    AS-->>User: Redirect to upstream provider
    User->>IdP: Authenticate
    IdP-->>AS: /identity/callback + authorization code
    AS->>IdP: Redeem upstream code
    alt Connector requests openid
        AS->>AS: Verify ID token signature, claims, and nonce
    else Plain OAuth 2.0 connector
        AS->>IdP: Fetch userinfo
    end
    AS->>Store: Persist resolved identity and upstream session
    AS-->>User: Redirect to client callback + MCP authorization code
    User->>Client: Follow redirect
    Client->>AS: /token + code verifier
    AS->>Store: Consume code and verify PKCE
    AS-->>Client: MCP access and refresh tokens
```

A connector only needs `issuer` plus whichever of `authorization_endpoint`,
`token_endpoint`, `jwks_uri`, and `userinfo_endpoint` it doesn't want to
specify by hand: at load time, if any of the first three is missing, the
server fetches `{issuer}/.well-known/openid-configuration` (OpenID Connect
Discovery 1.0) once and fills in whichever fields the connector left blank.
A connector that already specifies all three never triggers this — it's
purely additive, so every connector written before discovery existed keeps
working unchanged. A load-time failure to reach the discovery document is a
startup error, not a silent fallback.

`identity_claims` is the ordered list of ID token claims tried, in order, as
the local identity (`Identity.Subject`): defaults to `["sub"]`. Not every
provider puts a usable identity in the ID token itself — some only expose
`email` or group membership via the userinfo endpoint, and `sub` is often an
opaque per-provider identifier a resource server has no other use for. If
none of `identity_claims` are present in the ID token and `userinfo_endpoint`
is known (explicit or discovered), it's called once with the upstream access
token — never the MCP client's own token — and its claims are merged in
before trying again; ID token claims always win over userinfo's on overlap,
since userinfo responses aren't signed the way ID tokens are.

`allowed_algorithms` lists which JWS algorithms this connector's ID tokens
may be signed with: any of `RS256`, `PS256`, `ES256`. Defaults to `["RS256"]`
when unset, matching every connector configured before this field existed —
a provider that signs with ES256 or PS256 needs it set explicitly.

### OIDC or plain OAuth 2.0

Requesting the `openid` scope is what makes a connector OIDC, and that is how
the server decides what to require:

- **With `openid`** (including a connector that sets no `scopes` at all, since
  the authorization request defaults to `openid`): the provider must return an
  `id_token`, and it is verified — signature against the JWKS, issuer,
  audience, expiry, `iat`/`nbf`, and the nonce binding it to this request. A
  response with no `id_token` is an error, not a fallback: it means the
  provider misbehaved or someone removed `openid` from the scopes, and quietly
  accepting less verification is the wrong answer to either.
- **Without `openid`** (a GitHub-style OAuth 2.0 provider): there is no ID
  token, so identity comes from `userinfo_endpoint`, called once with the
  upstream access token and resolved through `identity_claims`. Such a
  connector must set `userinfo_endpoint` (directly or via discovery) and
  `identity_claims` naming a claim that endpoint actually returns, or startup
  succeeds and the first login fails. The state is still one-time and
  store-consumed, and PKCE still binds the code exchange; only the ID token's
  own nonce binding is absent, because there is no ID token.

`downstream_token_strategy` selects how a resource server's downstream
credential (the one it sends to the actual downstream API — Databricks, an
internal service, whatever the connector fronts) is obtained:

- `upstream_session` (the default): the token set the connector's upstream
  provider already issued at login is captured, persisted per subject, reused
  directly, and refreshed via `grant_type=refresh_token` when it expires. This
  works with any OAuth2/OIDC provider, since it never depends on the upstream
  supporting RFC 8693 token-exchange or trusting an mcp-auth-issued token as a
  federated subject. Its limit: it can only return the credential the login
  session already produced — it can't mint one for an audience/scope that
  session wasn't already requested with.
- `rfc8693`: performs RFC 8693 token-exchange against the connector's upstream
  provider, presenting this server's own access token as `subject_token`. Use
  this only against a provider that actually implements token-exchange (often
  requiring pre-configured issuer federation) and where a per-request,
  differently-scoped downstream token is genuinely needed.

If unsure which a specific upstream provider supports, start with
`upstream_session` — it needs nothing beyond what an ordinary Authorization
Code + PKCE login already requires.

A connector has two independent, optional redirect allowlists that are easy to
conflate because they're both "redirect URIs":

- `allowed_upstream_callback_uris`: which of this server's own
  `MCP_AUTH_ISSUER`-derived `/identity/callback` URLs may be used when
  registering with the connector's upstream provider. This guards the
  server's own registration, not an MCP client's redirect.
- `allowed_client_redirect_uris`: which `redirect_uris` an MCP client (Cursor,
  Claude Desktop, ...) may request through dynamic client registration, in
  addition to the HTTPS-or-loopback check `POST /register` always applies.
  Leave it empty for clients that use a loopback listener on an
  unpredictable port, since an allowlist can only match exact values.

## Verified identity providers

The server is provider-neutral by construction, but "neutral" is only a claim
until it is run against providers that share no code. These were verified end
to end — dynamic client registration, consent, upstream login, ID token
verification, `upstream_session` storage, MCP token issuance, and an
authenticated `tools/call` on a resource server — changing **nothing but the
connector entry**.

| Provider | Result | Notes |
| --- | --- | --- |
| Keycloak 26 | verified | Signs RS256. Sets session cookies `SameSite=None`, which forces `Secure`; browsers treat `http://localhost` as a secure context, non-browser test harnesses often do not. |
| Dex | verified | Signs RS256. `skipApprovalScreen: true` removes a second consent step that is redundant when this server already renders one. |
| GitLab CE 18 | verified | Signs RS256. Shows its own approval page on first authorization, then answers an already-authorized app with a *200 HTML redirect page* rather than a 302 — so a first run and a repeat run take different shapes. Its sign-in form is server-rendered entirely as `type="hidden"` inputs that Vue fills in, so field names (`user[login]`, `user[password]`) matter and input types do not. OAuth applications require an `organization_id` from GitLab 17 on. |
| Authelia | not supported on plaintext loopback | Refuses a cookie domain without a period and requires an HTTPS `authelia_url`. An Authelia policy, not a limitation here; it needs a dotted hostname and TLS. |

Each was driven through the same ten checks — dynamic client registration,
consent, upstream login, `/identity/callback`, token issuance, and an
authenticated `initialize`, `tools/list` and `tools/call` — twice per provider,
because several providers behave differently once an authorization is
remembered.

### Split public and internal endpoints

A connector's endpoints are configured individually, which matters more than it
first appears. The browser and this server usually reach a provider by
different names — the browser through a published address, this server over an
internal network — and only the browser-facing ones may be rewritten:

```json
{
  "issuer": "http://localhost:6350/realms/mcp",
  "authorization_endpoint": "http://localhost:6350/realms/mcp/protocol/openid-connect/auth",
  "token_endpoint": "http://keycloak.internal:6350/realms/mcp/protocol/openid-connect/token",
  "jwks_uri": "http://keycloak.internal:6350/realms/mcp/protocol/openid-connect/certs"
}
```

`issuer` and `authorization_endpoint` must be what the **browser** resolves,
because `issuer` is compared against the ID token's `iss` claim and the user is
redirected to `authorization_endpoint`. `token_endpoint` and `jwks_uri` are
back-channel calls this server makes itself, so they take the internal name.

Leaving the back-channel endpoints blank triggers discovery instead, which is
simpler — but discovery resolves them relative to `issuer`, so it only works
when one name reaches the provider from both sides.

### Loopback deployments

`localhost` and `127.0.0.1` are different strings to an issuer or audience
comparison even though they resolve to the same host, so `MCP_AUTH_ISSUER`,
`MCP_AUTH_RESOURCE`, the connector's `allowed_upstream_callback_uris`, the
redirect URI registered with the upstream provider, and the URL handed to the
MCP client must all agree on one spelling. Publishing a container port with
`-p 127.0.0.1:…` binds IPv4 only, so a client resolving `localhost` to `::1`
will fail to connect with no useful error.

## Persistence

`MemoryStore` is for local development and tests. `SQLiteStore` persists clients,
consent requests, authorization codes, and refresh-token hashes transactionally
for a single server instance. Refresh-token families are revoked together when
reuse is detected. A multi-replica production deployment must use a
shared managed database adapter implementing `Store`; the HTTP handlers do not
depend on SQLite. Authorization codes and consent state are one-time and
short-lived. Refresh tokens are opaque, hashed, rotated on use, and revoked when
reuse is detected.

**`upstream_sessions` is the one exception to "the store never holds a usable
secret."** The `upstream_session` downstream-token strategy needs to replay the
upstream provider's own access/refresh token later, so unlike every other
table it stores that token set directly, not a hash. Treat this table with the
same care as the signing key: it belongs in a store with encryption at rest
and restricted access, not an unencrypted Docker volume, and a leak of it is
equivalent to a leak of every affected user's downstream credential.

```mermaid
flowchart TB
    handlers["OAuth handlers"]
    store["Store interface"]
    memory[("MemoryStore<br/>tests and local development")]
    sqlite[("SQLiteStore<br/>single-node durable deployment")]
    managed[("Shared encrypted store<br/>multi-replica production")]
    keys["KeyProvider interface"]
    localKeys["Local PEM / ephemeral key<br/>development"]
    managedKeys["KMS, HSM, or secret manager<br/>production"]

    handlers --> store
    store --> memory
    store --> sqlite
    store -.->|"custom adapter"| managed
    handlers --> keys
    keys --> localKeys
    keys -.->|"custom adapter"| managedKeys
```

The store contains different classes of data:

- One-time authorization codes, consent state, and OAuth state.
- Hashed refresh tokens, with rotation and reuse detection.
- Dynamic client registrations.
- **Usable upstream access and refresh tokens** when
  `downstream_token_strategy=upstream_session`; protect these as credentials.

The local token exchanger exists only to make the development Compose flow
self-contained. Production must inject a provider-backed `TokenExchanger` that
validates the subject token and obtains a credential for the downstream audience.

Do not use a Docker volume as the authoritative credential/state store for a multi-instance deployment. Volumes are node-local and create failover, backup, encryption, and access-control problems. A volume is acceptable only as a tightly controlled single-node development or explicitly managed single-node deployment choice. The enterprise default is a shared encrypted database for OAuth state and a secret manager/KMS/HSM for signing keys and confidential client credentials. Implement `Store` and `KeyProvider` adapters for the chosen services; the HTTP handlers do not change.

The built-in `LocalKeyProvider` wraps the development PEM loader and ephemeral generated key. Production should replace it with a `KeyProvider` backed by KMS/HSM signing or a secret manager with rotation support. The server never needs to persist raw refresh tokens or client secrets: it stores hashes, and the secret provider owns private key material.

## Serving multiple resources

One `auth-server` process is deliberately scoped to exactly one connector and
one `MCP_AUTH_RESOURCE`: `Config.Resource` is a single value, `/authorize`
rejects any `resource` parameter that doesn't match it exactly, and
`MCP_AUTH_CONNECTOR` selects exactly one entry out of `MCP_AUTH_CONNECTORS_FILE`
even when that file defines several. A connectors file with multiple entries
is for choosing between them across deployments (a staging connector and a
production connector, say), not for one running server to serve several
resources at once.

To front more than one resource server or upstream provider, run one
`auth-server` process per resource — each with its own `MCP_AUTH_CONNECTOR`,
`MCP_AUTH_RESOURCE`, and `MCP_AUTH_LISTEN_ADDR` — behind a shared reverse
proxy that routes by hostname or path. Nothing in the current design prevents
this; it's an ordinary multi-instance deployment; only the routing in front
of it changes. For example, with Caddy routing by hostname:

```mermaid
flowchart LR
    proxy["Shared HTTPS reverse proxy"]
    authA["auth-server :8081<br/>connector=inventory<br/>resource=/inventory/mcp"]
    authB["auth-server :8082<br/>connector=internal-api<br/>resource=/internal-api/mcp"]
    dbA[("State and keys A")]
    dbB[("State and keys B")]

    proxy -->|"inventory-auth.example.com"| authA
    proxy -->|"internal-api-auth.example.com"| authB
    authA --> dbA
    authB --> dbB
```

```caddyfile
inventory-auth.example.com {
    reverse_proxy 127.0.0.1:8081
}

internal-api-auth.example.com {
    reverse_proxy 127.0.0.1:8082
}
```

Each backend is a separate `auth-server` process, e.g.:

```bash
MCP_AUTH_ISSUER=https://inventory-auth.example.com \
MCP_AUTH_RESOURCE=https://mcp.example.com/inventory/mcp \
MCP_AUTH_CONNECTOR=inventory \
MCP_AUTH_LISTEN_ADDR=127.0.0.1:8081 \
go run ./auth-server/cmd/auth-server &

MCP_AUTH_ISSUER=https://internal-api-auth.example.com \
MCP_AUTH_RESOURCE=https://mcp.example.com/internal-api/mcp \
MCP_AUTH_CONNECTOR=internal-api \
MCP_AUTH_LISTEN_ADDR=127.0.0.1:8082 \
go run ./auth-server/cmd/auth-server &
```

Each instance needs its own `MCP_AUTH_DATABASE_URL` (or its own credentials
to a shared database) so their client registrations, consent state, and
signing keys don't collide.

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
