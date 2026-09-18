import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  AuthenticationError,
  JWTVerifier,
  TokenExchangeClient,
  authenticateRequest,
  bearerChallenge,
  protectedResourceMetadata,
} from "../src/index.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = publicKey.export({ format: "jwk" });
const issuer = "https://auth.example.com";
const audience = "https://mcp.example.com/mcp";

function jwt(overrides: Record<string, unknown> = {}): string {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({ alg: "RS256", typ: "at+jwt", kid: "test-key" });
  const claims = encode({
    iss: issuer, aud: audience, sub: "user-123", scope: "tools:read profile",
    exp: Math.floor(Date.now() / 1000) + 300, ...overrides,
  });
  const message = `${header}.${claims}`;
  return `${message}.${sign("RSA-SHA256", Buffer.from(message), privateKey).toString("base64url")}`;
}

function verifier(requiredScopes = ["tools:read"]): JWTVerifier {
  return new JWTVerifier({
    jwksUri: `${issuer}/.well-known/jwks.json`, issuer, audience, requiredScopes,
    fetch: async () => new Response(JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] })),
  });
}

test("verifies signature, issuer, audience, subject, expiry, and scopes", async () => {
  const claims = await verifier().verify(jwt());
  assert.equal(claims.subject, "user-123");
  assert.deepEqual([...claims.scopes], ["tools:read", "profile"]);
  await assert.rejects(verifier().verify(jwt({ aud: "https://other.example.com" })), /audience/);
  await assert.rejects(verifier().verify(jwt({ exp: 1 })), /expired/);
  await assert.rejects(verifier(["tools:write"]).verify(jwt()), /required scopes/);
});

test("authenticates Node requests and distinguishes missing scope", async () => {
  const claims = await authenticateRequest({ headers: { authorization: `Bearer ${jwt()}` } }, verifier());
  assert.equal(claims.subject, "user-123");
  await assert.rejects(
    authenticateRequest({ headers: { authorization: `Bearer ${jwt()}` } }, verifier(["tools:write"])),
    (error: unknown) => error instanceof AuthenticationError && error.status === 403,
  );
});

test("derives stable metadata and escapes bearer challenges", () => {
  assert.deepEqual(protectedResourceMetadata(verifier(["tools:write", "tools:read"]), audience, issuer), {
    resource: audience,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: ["tools:read", "tools:write"],
  });
  assert.equal(bearerChallenge("https://example.com/\"metadata"), 'Bearer resource_metadata="https://example.com/\\"metadata"');
});

test("exchanges and caches a downstream token", async () => {
  let calls = 0;
  const client = new TokenExchangeClient({
    endpoint: `${issuer}/token`,
    fetch: async (_input, init) => {
      calls++;
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get("grant_type"), "urn:ietf:params:oauth:grant-type:token-exchange");
      assert.equal(body.get("audience"), "https://api.example.com");
      return new Response(JSON.stringify({ access_token: "downstream", expires_in: 300, scope: "read" }));
    },
  });
  const first = await client.exchange("subject-token", "https://api.example.com", ["read"]);
  const second = await client.exchange("subject-token", "https://api.example.com", ["read"]);
  assert.equal(first.accessToken, "downstream");
  assert.equal(second, first);
  assert.equal(calls, 1);
});
