import { createPublicKey, verify as verifySignature, type JsonWebKey } from "node:crypto";
import { isIP } from "node:net";

const MAX_JWKS_BYTES = 1024 * 1024;

export class TokenVerificationError extends Error {
  constructor(message = "invalid MCP access token", options?: ErrorOptions) {
    super(message, options);
    this.name = "TokenVerificationError";
  }
}

export interface TokenClaims {
  subject: string;
  issuer: string;
  audience: string[];
  scopes: ReadonlySet<string>;
  claims: Readonly<Record<string, unknown>>;
}

export interface JWTVerifierOptions {
  jwksUri: string;
  issuer: string;
  audience: string;
  requiredScopes?: Iterable<string>;
  fetch?: typeof globalThis.fetch;
  jwksTtlMs?: number;
  clockSkewSeconds?: number;
  ssrfSafe?: boolean;
}

interface JWKSDocument { keys: JsonWebKey[] }

function decodePart(value: string): Record<string, unknown> {
  try {
    const decoded: unknown = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error();
    return decoded as Record<string, unknown>;
  } catch (error) {
    throw new TokenVerificationError("JWT contains invalid JSON", { cause: error });
  }
}

function audiences(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return value;
  return [];
}

export class JWTVerifier {
  readonly jwksUri: string;
  readonly issuer: string;
  readonly audience: string;
  readonly requiredScopes: ReadonlySet<string>;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly jwksTtlMs: number;
  private readonly clockSkewSeconds: number;
  private readonly ssrfSafe: boolean;
  private keys = new Map<string, JsonWebKey>();
  private loadedAt = 0;
  private loading: Promise<void> | undefined;

  constructor(options: JWTVerifierOptions) {
    this.jwksUri = options.jwksUri;
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.requiredScopes = new Set(options.requiredScopes ?? []);
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.jwksTtlMs = options.jwksTtlMs ?? 300_000;
    this.clockSkewSeconds = options.clockSkewSeconds ?? 60;
    this.ssrfSafe = options.ssrfSafe ?? true;
  }

  async verify(token: string, signal?: AbortSignal): Promise<TokenClaims> {
    const parts = token.split(".");
    if (parts.length !== 3) throw new TokenVerificationError();
    const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
    const header = decodePart(encodedHeader);
    const claims = decodePart(encodedPayload);
    if (header.alg !== "RS256") throw new TokenVerificationError("JWT algorithm is not allowed");
    if (header.typ !== undefined && header.typ !== "JWT" && header.typ !== "at+jwt") {
      throw new TokenVerificationError("JWT type is not allowed");
    }
    if (typeof header.kid !== "string" || !header.kid) throw new TokenVerificationError("JWT kid is missing");

    let jwk = await this.key(header.kid, false, signal);
    if (!jwk) jwk = await this.key(header.kid, true, signal);
    if (!jwk) throw new TokenVerificationError("JWT signing key was not found");
    let validSignature = false;
    try {
      validSignature = verifySignature(
        "RSA-SHA256",
        Buffer.from(`${encodedHeader}.${encodedPayload}`),
        createPublicKey({ key: jwk, format: "jwk" }),
        Buffer.from(encodedSignature, "base64url"),
      );
    } catch (error) {
      throw new TokenVerificationError("JWT signing key is invalid", { cause: error });
    }
    if (!validSignature) throw new TokenVerificationError("JWT signature is invalid");

    const now = Date.now() / 1000;
    if (claims.iss !== this.issuer) throw new TokenVerificationError("JWT issuer is invalid");
    if (typeof claims.exp !== "number" || now > claims.exp + this.clockSkewSeconds) {
      throw new TokenVerificationError("JWT is expired");
    }
    if (typeof claims.nbf === "number" && now + this.clockSkewSeconds < claims.nbf) {
      throw new TokenVerificationError("JWT is not active");
    }
    const tokenAudiences = audiences(claims.aud);
    if (!tokenAudiences.includes(this.audience)) throw new TokenVerificationError("JWT audience is invalid");
    if (typeof claims.sub !== "string" || !claims.sub) throw new TokenVerificationError("JWT subject is missing");
    const scopes = new Set(typeof claims.scope === "string" ? claims.scope.split(/\s+/).filter(Boolean) : []);
    for (const scope of this.requiredScopes) {
      if (!scopes.has(scope)) throw new TokenVerificationError("JWT does not contain all required scopes");
    }
    return { subject: claims.sub, issuer: this.issuer, audience: tokenAudiences, scopes, claims };
  }

  private async key(kid: string, force: boolean, signal?: AbortSignal): Promise<JsonWebKey | undefined> {
    if (force || this.keys.size === 0 || Date.now() - this.loadedAt >= this.jwksTtlMs) await this.load(signal);
    return this.keys.get(kid);
  }

  private async load(signal?: AbortSignal): Promise<void> {
    if (this.loading) return this.loading;
    this.validateJwksUri();
    this.loading = (async () => {
      try {
        const init: RequestInit = { headers: { accept: "application/json" }, redirect: "error" };
        if (signal) init.signal = signal;
        const response = await this.fetcher(this.jwksUri, init);
        if (!response.ok) throw new Error(`JWKS returned HTTP ${response.status}`);
        const text = await response.text();
        if (Buffer.byteLength(text) > MAX_JWKS_BYTES) throw new Error("JWKS response is too large");
        const document: unknown = JSON.parse(text);
        if (!document || typeof document !== "object" || !Array.isArray((document as JWKSDocument).keys)) {
          throw new Error("JWKS response is invalid");
        }
        const next = new Map<string, JsonWebKey>();
        for (const key of (document as JWKSDocument).keys) {
          if (key.kty === "RSA" && typeof key.kid === "string") next.set(key.kid, key);
        }
        this.keys = next;
        this.loadedAt = Date.now();
      } catch (error) {
        throw new TokenVerificationError("unable to load JWKS", { cause: error });
      } finally {
        this.loading = undefined;
      }
    })();
    return this.loading;
  }

  private validateJwksUri(): void {
    let url: URL;
    try { url = new URL(this.jwksUri); } catch { throw new TokenVerificationError("JWKS URI must be absolute"); }
    if (!['http:', 'https:'].includes(url.protocol)) throw new TokenVerificationError("JWKS URI must use HTTP(S)");
    if (!this.ssrfSafe) return;
    if (url.username || url.password) throw new TokenVerificationError("JWKS URI must not contain credentials");
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !loopback) throw new TokenVerificationError("JWKS URI must use HTTPS");
    if (isIP(url.hostname.replace(/^\[|\]$/g, "")) && !loopback) {
      throw new TokenVerificationError("JWKS URI must not use a non-loopback IP address");
    }
  }
}
