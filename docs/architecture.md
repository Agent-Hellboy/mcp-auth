# Architecture

## Components

`auth-server` is an independently deployable Go OAuth authorization server. It owns authorization codes, consent, access-token signing, refresh-token rotation, client registration, and authorization-server metadata.

`auth-client/python` and `auth-client/go` are resource-server SDKs. They validate access tokens issued by any compatible authorization server and provide discovery, challenge, and token-exchange helpers. They do not require the bundled authorization server.

Provider integrations implement `IdentityProvider` or `TokenExchanger` interfaces. Provider-specific claims, SDKs, and policy remain outside the core server and SDKs.

## MCP request flow

1. The MCP client calls an HTTP MCP endpoint without a token.
2. The resource server responds `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.
3. The client fetches Protected Resource Metadata and selects an authorization server.
4. The client fetches Authorization Server Metadata.
5. The client registers, if supported, and opens Authorization Code + PKCE with `resource` set to the canonical MCP resource URI.
6. The authorization server validates the redirect URI, PKCE challenge, consent, and scope. It can include the RFC 9207 `iss` response parameter for newer MCP clients while remaining compatible with clients that ignore unknown authorization response parameters.
7. The client redeems the code. The server returns a short-lived JWT access token and a rotating refresh token.
8. The client sends the access token in the `Authorization` header on every MCP request.
9. The resource server validates signature, issuer, audience/resource, expiry, and scope using JWKS.

Authorization is optional in MCP. A resource server may require it based on the sensitivity of the data or actions it exposes.

Compatibility follows the shared authorization flow in the [2025-06-18 MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) and the [2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). Newer issuer-response validation is additive, so deployments can support clients from either version.

## Token boundaries

There are three different credentials:

| Credential | Issued for | Allowed use |
| --- | --- | --- |
| MCP client token | The MCP resource server | Inbound resource-server authorization |
| Resource-server service credential | A downstream authorization server/API | Server-to-server authentication |
| Downstream API token | The downstream API audience | Requests to that downstream API only |

The resource server must never forward the MCP client token to an API with a different audience. Use RFC 8693 token exchange or another provider adapter to mint a separate downstream token.

## Extensibility

- `Store` allows durable persistence without changing handlers. OAuth state belongs in a shared managed store for multi-instance deployments.
- `KeyProvider` allows KMS/HSM or secret-manager-backed signing and JWKS publication; local PEM/ephemeral keys are for development only.
- `IdentityProvider` allows local development, OIDC, SAML-backed login, or another user system.
- `TokenExchanger` allows RFC 8693 or provider-specific downstream exchange.
- SDK discovery objects accept third-party authorization-server metadata.
- FastMCP is optional in the Python package; non-FastMCP servers can use the verifier and challenge helpers directly.
