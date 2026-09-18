# Auth client SDKs

Both SDKs are installable without the authorization server. They work with the bundled server or a third-party OAuth authorization server that publishes compatible metadata.

The SDK is the authorization boundary inside a resource server. MCP tool handlers
receive a verified subject and scopes; they do not parse bearer tokens, fetch JWKS,
or know which identity provider authenticated the caller.

```mermaid
flowchart LR
    client["MCP client"]

    subgraph server["MCP resource server"]
        challenge["401 challenge + metadata"]
        verifier["JWTVerifier"]
        policy["Audience + scope policy"]
        tools["MCP tool handlers"]

        challenge --> verifier --> policy --> tools
    end

    auth["Compatible authorization server<br/>metadata, JWKS, token endpoint"]
    downstream["Downstream API"]

    client -->|"Request without token"| challenge
    challenge -.->|"WWW-Authenticate"| client
    client -->|"Bearer MCP token"| verifier
    verifier -.->|"Bounded JWKS refresh"| auth
    tools -->|"Separate downstream token"| downstream
```

The Python package is currently Git-installable (a VCS pin is appropriate until
the package is published to an index):

```bash
python -m pip install "mcp-auth-client @ git+https://github.com/Agent-Hellboy/mcp-auth.git#subdirectory=auth-client/python"
```

## Python

```python
from mcp_auth_client import JWTVerifier, RemoteAuthProvider

verifier = JWTVerifier(
    jwks_uri="https://auth.example.com/.well-known/jwks.json",
    issuer="https://auth.example.com",
    audience="https://mcp.example.com",
    required_scopes={"tools:read"},
)
auth = RemoteAuthProvider(
    token_verifier=verifier,
    authorization_servers=["https://auth.example.com"],
    base_url="https://mcp.example.com",
).build()
```

Install the FastMCP extra only when using FastMCP. Otherwise call `JWTVerifier.verify` and return `unauthorized_headers(...)` from the resource server's 401 response.

The verifier is explicitly RS256-only, refreshes JWKS on a bounded schedule, validates `iss`, `aud`, `exp`, `nbf`, `sub`, and required scopes, and rejects unknown signing keys. `VerifyContext` and `RequireToken` propagate request cancellation and emit standards-compliant bearer challenges.

`build_remote_auth`, `build_exchange_client`, `public_base_url`,
`TokenExchangeError`, and `ExchangedToken` are part of the SDK itself. The
`ssrf_safe` option controls the JWKS fetch policy: safe mode requires HTTPS for
non-loopback endpoints and rejects credential-bearing or non-loopback IP URLs;
disable it only for a controlled local test transport.

## Go

Import `github.com/Agent-Hellboy/mcp-auth/auth-client/go/mcpauth`, configure `JWTVerifier`, and use `DiscoverProtectedResource`, `DiscoverAuthorizationServer`, `ParseWWWAuthenticate`, and `TokenExchangeClient`. The Go SDK uses the standard library and supports bounded token caching. Install the client module at the `auth-client/go/v0.1.0` release tag.

## Publishing protected resource metadata

Every MCP resource server must publish an RFC 9728 document saying which
authorization servers issue its tokens. The MCP authorization spec requires the
`authorization_servers` field; in practice `scopes_supported` matters just as
much, because it is the only thing that tells a client which scope to request.

Omit it and the failure is quiet and misleading: the client asks for no scope,
the authorization server issues a token with an empty `scope`, and every call
is refused with `403`. Nothing in that exchange says a scope was missing, so it
reads as broken authentication. Cursor surfaces it as
`Server returned 403 after trying upscoping` — it tried to escalate and had
nothing to escalate to.

Both SDKs therefore derive the document from the verifier that guards the
resource, so the advertised scopes cannot drift from the enforced ones.

**Go**

```go
verifier := &mcpauth.JWTVerifier{
    JWKSURL:        jwksURL,
    Issuer:         issuer,
    Audience:       resource,
    RequiredScopes: map[string]bool{"tools:read": true},
}

metadata := mcpauth.ProtectedResourceMetadataHandler(verifier, resource, issuer)
mux.Handle("/.well-known/oauth-protected-resource"+mcpPath, metadata)
mux.Handle("/.well-known/oauth-protected-resource", metadata)
mux.Handle(mcpPath, mcpauth.RequireToken(verifier, mcpauth.ResourceMetadata{URL: metadataURL}, handler))
```

**Python**

```python
verifier = JWTVerifier(
    jwks_uri=jwks_url, issuer=issuer, audience=resource, required_scopes={"tools:read"}
)
document = protected_resource_metadata(verifier, resource, issuer)
```

Mount it on both the bare well-known path and the path-suffixed form: clients
build the URL from the resource identifier, so a resource at `/ping/mcp` is
looked up at `/.well-known/oauth-protected-resource/ping/mcp`.

On FastMCP, `build_remote_auth(..., scopes_supported=[...])` already serves the
document; pass the same scopes the verifier enforces.

### Challenges

`RequireToken` (Go) emits both challenges for you. Serving the HTTP layer
yourself means emitting them yourself:

| Situation | Status | Helper |
|---|---|---|
| No or malformed `Authorization` header | 401 | `unauthorized_headers(metadata_url)` |
| Token fails signature, `iss`, `aud`, or `exp` | 401 | `unauthorized_headers_for_error(..., "invalid_token", ...)` |
| Token is valid but lacks a required scope | 403 | `unauthorized_headers_for_error(..., "insufficient_scope", ...)` |

The `insufficient_scope` code is what separates "you may retry with more scope"
from "this token is rejected". Without it a client cannot tell the two apart and
will not retry.

A runnable example of the plain (non-FastMCP) Python path, including both
challenges and the metadata document, lives in the MCP Runtime repository at
`examples/mcp-auth-sdk-ping-py`; its Go counterpart is
`examples/mcp-auth-sdk-ping`.

## Discovery and third-party providers

Resource servers should publish Protected Resource Metadata with `authorization_servers`. Clients then fetch `/.well-known/oauth-authorization-server` from the selected issuer. The SDK metadata dataclasses and structs accept provider-neutral endpoints, optional DCR, optional revocation, and provider-specific scope sets without changing MCP tools.

The repository includes a Docker Compose E2E flow with the in-tree dummy
resource server, deployable `mcp-auth`, Keycloak as the identity provider, a
runtime key helper, and an SDK client. It covers both MCP authorization response
variants, consent, Keycloak login, PKCE, JWT/JWKS validation, upstream-session
token exchange, refresh rotation, revocation, invalid-token rejection, and MCP
initialization. Run it with:

```bash
docker compose -f deploy/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from e2e-client
docker compose -f deploy/docker-compose.e2e.yml down --volumes --remove-orphans
```

## Token exchange

`TokenExchangeClient` sends RFC 8693 parameters and returns a token tagged with the requested downstream audience. Cache keys are bounded and include subject-token identity, audience, and scope. The returned token is a new downstream credential; do not substitute the inbound MCP client token. Keep these boundaries explicit: the MCP client token authenticates the caller to the resource server, the resource server's service credential authenticates its exchange request, and the downstream API token authenticates the provider call.

```mermaid
sequenceDiagram
    autonumber
    participant Client as MCP client
    participant RS as Resource server + SDK
    participant AS as Authorization server
    participant API as Downstream API

    Client->>RS: MCP request + MCP access token
    RS->>RS: Verify signature, iss, aud, exp, sub, scopes
    RS->>AS: RFC 8693 token exchange<br/>subject_token + private_key_jwt
    AS->>AS: Validate MCP token and resource-server assertion
    AS-->>RS: Downstream access token
    RS->>API: Request + downstream access token
    API-->>RS: Provider response
    RS-->>Client: MCP result
```

The SDK cache is keyed by subject-token identity, requested audience, and scope.
It never turns an MCP token into a generic bearer credential, and it never sends
the resource server's private key to the authorization server.

## Private-key JWT

`PrivateKeyJWTClientAuth` creates short-lived `client_assertion` JWTs with `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, and `kid`. Keep the private key outside the repository and load it from a secret manager or file with restrictive permissions.

## Extension points

Implement a provider adapter around the SDK's metadata and HTTP interfaces when a third-party authorization server has non-standard registration or exchange behavior. Keep the adapter at the application edge; MCP tool handlers should receive verified subject/scopes and never know which provider issued the token.
