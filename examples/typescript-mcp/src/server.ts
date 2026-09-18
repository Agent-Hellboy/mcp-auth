import { createServer, type ServerResponse } from "node:http";
import {
  AuthenticationError,
  JWTVerifier,
  authenticateRequest,
  bearerChallenge,
  protectedResourceMetadata,
} from "@mcp-auth/client";

const issuer = process.env.MCP_AUTH_ISSUER ?? "http://localhost:8080";
const port = Number(process.env.MCP_PORT ?? 8081);
const resource = process.env.MCP_RESOURCE ?? `http://localhost:${port}/mcp`;
const metadataUrl = new URL("/.well-known/oauth-protected-resource/mcp", resource).toString();
const verifier = new JWTVerifier({
  issuer,
  audience: resource,
  jwksUri: process.env.MCP_AUTH_JWKS_URI ?? `${issuer}/.well-known/jwks.json`,
  requiredScopes: ["tools:read"],
});

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

const server = createServer(async (request, response) => {
  if (request.method === "GET" && ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"].includes(request.url ?? "")) {
    return json(response, 200, protectedResourceMetadata(verifier, resource, issuer));
  }
  if (request.method !== "POST" || request.url !== "/mcp") return json(response, 404, { error: "not_found" });

  let claims;
  try {
    claims = await authenticateRequest(request, verifier);
  } catch (error) {
    const authError = error instanceof AuthenticationError ? error : new AuthenticationError(401, "invalid_token", "Unauthorized");
    response.setHeader("WWW-Authenticate", bearerChallenge(metadataUrl, authError.code, authError.message));
    return json(response, authError.status, { error: authError.code });
  }

  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  let message: { id?: unknown; method?: unknown };
  try { message = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { return json(response, 400, { jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }); }

  if (message.method === "initialize") {
    return json(response, 200, { jsonrpc: "2.0", id: message.id, result: {
      protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "typescript-mcp", version: "0.3.0" },
    } });
  }
  if (message.method === "tools/list") {
    return json(response, 200, { jsonrpc: "2.0", id: message.id, result: { tools: [{
      name: "whoami", description: "Return the authenticated MCP subject", inputSchema: { type: "object", properties: {} },
    }] } });
  }
  if (message.method === "tools/call") {
    return json(response, 200, { jsonrpc: "2.0", id: message.id, result: {
      content: [{ type: "text", text: JSON.stringify({ subject: claims.subject, scopes: [...claims.scopes] }) }],
    } });
  }
  return json(response, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } });
});

server.listen(port, "0.0.0.0", () => console.log(`TypeScript MCP server listening at ${resource}`));
