import assert from "node:assert/strict";
import { createPrivateKey, sign, type JsonWebKey, type KeyObject } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { JWTVerifier, TokenVerificationError } from "../src/index.js";

interface ConformanceCase {
  id: string;
  kind?: string;
  expect: "accept" | "reject";
  header?: Record<string, unknown>;
  claims?: Record<string, unknown>;
  exp_offset_seconds?: number;
  nbf_offset_seconds?: number;
  clock_skew_seconds?: number;
  required_scopes?: string[];
}

interface ConformanceSuite {
  max_jwks_bytes: number;
  pad_char: string;
  pad_count: number;
  defaults: {
    issuer: string;
    audience: string;
    clock_skew_seconds: number;
    exp_offset_seconds: number;
    header: Record<string, unknown>;
    claims: Record<string, unknown>;
  };
  cases: ConformanceCase[];
}

function fixtureRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let step = 0; step < 6; step += 1) {
    const candidate = path.join(dir, "sdk-conformance");
    if (existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error("sdk-conformance fixtures not found");
}

const root = fixtureRoot();
const suite = JSON.parse(readFileSync(path.join(root, "cases.json"), "utf8")) as ConformanceSuite;
const privateJwk = JSON.parse(readFileSync(path.join(root, "key.json"), "utf8")) as JsonWebKey;
const jwks = JSON.parse(readFileSync(path.join(root, "jwks.json"), "utf8")) as { keys: JsonWebKey[] };
const privateKey: KeyObject = createPrivateKey({ key: privateJwk, format: "jwk" });

function signToken(header: Record<string, unknown>, claims: Record<string, unknown>): string {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const message = `${encode(header)}.${encode(claims)}`;
  return `${message}.${sign("RSA-SHA256", Buffer.from(message), privateKey).toString("base64url")}`;
}

function tokenFor(testCase: ConformanceCase): string {
  const header = { ...suite.defaults.header, ...testCase.header };
  const claims: Record<string, unknown> = { ...suite.defaults.claims, ...testCase.claims };
  const now = Math.floor(Date.now() / 1000);
  claims.exp = now + (testCase.exp_offset_seconds ?? suite.defaults.exp_offset_seconds);
  if (testCase.nbf_offset_seconds !== undefined) claims.nbf = now + testCase.nbf_offset_seconds;
  return signToken(header, claims);
}

function oversizedBody(): string {
  const body = JSON.stringify({
    keys: jwks.keys,
    pad: suite.pad_char.repeat(suite.pad_count),
  });
  assert.ok(Buffer.byteLength(body) > suite.max_jwks_bytes);
  return body;
}

for (const testCase of suite.cases) {
  test(`conformance ${testCase.id}`, async () => {
    const token = tokenFor(testCase);
    const skew = testCase.clock_skew_seconds ?? suite.defaults.clock_skew_seconds;
    const verifier = new JWTVerifier({
      jwksUri: "https://auth.example.com/.well-known/jwks.json",
      issuer: suite.defaults.issuer,
      audience: suite.defaults.audience,
      requiredScopes: testCase.required_scopes ?? [],
      clockSkewSeconds: skew,
      fetch: async () => new Response(testCase.kind === "oversized_jwks" ? oversizedBody() : JSON.stringify(jwks)),
    });
    if (testCase.expect === "accept") {
      const claims = await verifier.verify(token);
      assert.equal(claims.subject, "user");
      return;
    }
    await assert.rejects(verifier.verify(token), (error: unknown) => error instanceof TokenVerificationError);
  });
}
