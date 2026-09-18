import type { JWTVerifier } from "./verifier.js";

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: ["header"];
  scopes_supported?: string[];
}

export function protectedResourceMetadata(
  verifier: JWTVerifier | undefined,
  resource: string,
  issuer: string,
): ProtectedResourceMetadata {
  const scopes = [...(verifier?.requiredScopes ?? [])].sort();
  return {
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    ...(scopes.length ? { scopes_supported: scopes } : {}),
  };
}
