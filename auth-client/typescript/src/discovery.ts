export interface ProtectedResourceConfig {
  resource: string;
  authorization_servers: string[];
  scopes_supported?: string[];
}

export interface AuthorizationServerConfig {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
  revocation_endpoint?: string;
  scopes_supported?: string[];
}

async function getJson<T>(url: string, fetcher: typeof fetch): Promise<T> {
  const response = await fetcher(url, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`discovery returned HTTP ${response.status}`);
  return await response.json() as T;
}

export function protectedResourceMetadataUrl(resource: string): string {
  const url = new URL(resource);
  return `${url.origin}/.well-known/oauth-protected-resource${url.pathname === "/" ? "" : url.pathname}`;
}

export async function discoverProtectedResource(resource: string, fetcher = fetch): Promise<ProtectedResourceConfig> {
  return getJson(protectedResourceMetadataUrl(resource), fetcher);
}

export async function discoverAuthorizationServer(issuer: string, fetcher = fetch): Promise<AuthorizationServerConfig> {
  const url = new URL(issuer);
  const suffix = url.pathname === "/" ? "" : url.pathname;
  return getJson(`${url.origin}/.well-known/oauth-authorization-server${suffix}`, fetcher);
}
