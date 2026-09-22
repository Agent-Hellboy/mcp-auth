# Security model

What this server guarantees, and what your deployment still has to do.

## Authorization flow

- Authorization Code + PKCE (`S256`) is required for public clients; there is no
  implicit or password grant.
- `/authorize` matches the registered `redirect_uri` exactly. Registration
  accepts the RFC 8252 shapes — HTTPS, loopback `http`, and private-use schemes
  — which is what desktop MCP clients use. See
  [the deviation note](auth-server.md#client-registration-and-consent).
- The token-exchange grant requires the caller to authenticate as a
  pre-registered resource server (RFC 7523 `private_key_jwt`) and to present a
  `subject_token` this server itself issued. It is not an open relay to the
  upstream connector.
- The consent page names the client and labels a dynamically registered
  client's name unverified, because the application supplied `client_name`
  and this server has not verified it. The consent document and the
  expired-consent response (HTTP 400) send `Content-Security-Policy`
  (`default-src 'none'`, `style-src 'unsafe-inline'` for the page's own
  style element, `form-action 'self'`, `frame-ancestors 'none'`),
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
  `Cache-Control: no-store`. Connector `consent.website_url` and
  `consent.support_url` must be absolute `https` URLs; that is checked when
  the connector file is loaded. See
  [the consent page](auth-server.md#consent-page).

## Tokens

- Access tokens are short-lived `at+jwt` with issuer, audience/resource, scopes,
  and unique IDs. A token is bound to the single resource the client requested,
  so it is refused by any other resource server.
- Refresh tokens are opaque, hashed at rest, rotated on use, and the whole
  family is revoked on reuse.
- Verifiers are RS256-only, refresh JWKS on a bounded schedule, and validate
  `iss`, `aud`, `exp`, `nbf`, `sub`, and required scopes.
- Tokens, secrets, codes, keys, and assertions are redacted from audit logs.
- A resource server must never forward an inbound MCP token to a downstream API.
  See [token boundaries](architecture.md#token-boundaries).

## Transport

- `MCP_AUTH_REQUIRE_HTTPS` defaults to true and means TLS on this process's
  listener.
- `X-Forwarded-Proto` is set by the caller, so it is **not** accepted as proof
  of TLS unless `MCP_AUTH_TRUST_PROXY_TLS=true`. That setting is a claim that a
  trusted proxy terminates TLS and is the only route in; a NetworkPolicy,
  security group, or equivalent is what makes the claim true. Enabling it
  without restricting network access lets anything that can reach the process
  satisfy the HTTPS requirement with one header.

## What the deployment owns

- A persistent signing key from a secret manager, KMS, or HSM, with a rotation
  plan. The ephemeral development key is not usable in production.
- Durable shared storage. SQLite suits a single instance; multiple replicas need
  a shared database adapter, not an unencrypted volume.
- Restrictive CORS and trusted origins, rate limits, CSRF protection at the
  login boundary, secure cookies, and reverse-proxy request limits.
- The upstream identity provider: its realm or tenant, users, client
  credentials, availability, and certificates.

The [production checklist](auth-server.md#production-checklist) is the short
form of this page.
