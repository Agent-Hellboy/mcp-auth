import type { IncomingMessage } from "node:http";
import { TokenVerificationError, type JWTVerifier, type TokenClaims } from "./verifier.js";

export class AuthenticationError extends Error {
  constructor(
    readonly status: 401 | 403,
    readonly code: "invalid_token" | "insufficient_scope",
    message: string,
  ) { super(message); this.name = "AuthenticationError"; }
}

export async function authenticateRequest(
  request: Pick<IncomingMessage, "headers">,
  verifier: JWTVerifier,
  signal?: AbortSignal,
): Promise<TokenClaims> {
  const header = request.headers.authorization;
  const match = typeof header === "string" ? /^Bearer\s+(\S+)$/i.exec(header) : null;
  if (!match?.[1]) throw new AuthenticationError(401, "invalid_token", "Bearer token is required");
  try {
    return await verifier.verify(match[1], signal);
  } catch (error) {
    if (error instanceof TokenVerificationError && error.message.includes("required scopes")) {
      throw new AuthenticationError(403, "insufficient_scope", error.message);
    }
    throw new AuthenticationError(401, "invalid_token", "Bearer token is invalid");
  }
}
