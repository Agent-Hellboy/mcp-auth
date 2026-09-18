import { createHash, randomUUID, sign } from "node:crypto";

const EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

function encode(value: object): string { return Buffer.from(JSON.stringify(value)).toString("base64url"); }

export class PrivateKeyJWTClientAuth {
  constructor(
    readonly clientId: string,
    private readonly privateKey: string,
    readonly keyId: string,
    readonly audience?: string,
  ) {}

  assertion(tokenEndpoint: string, now = Math.floor(Date.now() / 1000)): string {
    const message = `${encode({ typ: "JWT", alg: "RS256", kid: this.keyId })}.${encode({
      iss: this.clientId, sub: this.clientId, aud: this.audience ?? tokenEndpoint,
      iat: now, exp: now + 300, jti: randomUUID(),
    })}`;
    return `${message}.${sign("RSA-SHA256", Buffer.from(message), this.privateKey).toString("base64url")}`;
  }
}

export interface ExchangedToken {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  audience: string;
  scopes: ReadonlySet<string>;
}

export interface TokenExchangeClientOptions {
  endpoint: string;
  clientAuth?: PrivateKeyJWTClientAuth;
  fetch?: typeof globalThis.fetch;
}

export class TokenExchangeClient {
  private readonly fetcher: typeof globalThis.fetch;
  private readonly cache = new Map<string, ExchangedToken>();
  constructor(private readonly options: TokenExchangeClientOptions) {
    new URL(options.endpoint);
    this.fetcher = options.fetch ?? globalThis.fetch;
  }

  async exchange(subjectToken: string, audience: string, scopes: Iterable<string> = []): Promise<ExchangedToken> {
    const sortedScopes = [...scopes].sort();
    const key = `${createHash("sha256").update(subjectToken).digest("base64url")}|${audience}|${sortedScopes.join(" ")}`;
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > Date.now() + 30_000) return cached;
    const form = new URLSearchParams({
      grant_type: EXCHANGE_GRANT, subject_token: subjectToken, subject_token_type: ACCESS_TOKEN_TYPE,
      requested_token_type: ACCESS_TOKEN_TYPE, audience, scope: sortedScopes.join(" "),
    });
    if (this.options.clientAuth) {
      form.set("client_id", this.options.clientAuth.clientId);
      form.set("client_assertion_type", ASSERTION_TYPE);
      form.set("client_assertion", this.options.clientAuth.assertion(this.options.endpoint));
    }
    const response = await this.fetcher(this.options.endpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form,
    });
    if (!response.ok) throw new Error(`token exchange returned HTTP ${response.status}`);
    const data = await response.json() as Record<string, unknown>;
    if (typeof data.access_token !== "string") throw new Error("token exchange response has no access_token");
    const expiresIn = typeof data.expires_in === "number" && data.expires_in > 0 ? data.expires_in : 300;
    const token: ExchangedToken = {
      accessToken: data.access_token,
      tokenType: typeof data.token_type === "string" ? data.token_type : "Bearer",
      expiresAt: Date.now() + expiresIn * 1000,
      audience,
      scopes: new Set(typeof data.scope === "string" ? data.scope.split(/\s+/).filter(Boolean) : []),
    };
    this.cache.set(key, token);
    return token;
  }
}
