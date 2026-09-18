package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"

	"github.com/Agent-Hellboy/mcp-auth/auth-client/go/mcpauth"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func main() {
	issuer := env("MCP_AUTH_ISSUER", "http://localhost:8080")
	port := env("MCP_PORT", "8081")
	resource := env("MCP_RESOURCE", "http://localhost:"+port+"/mcp")
	verifier := &mcpauth.JWTVerifier{
		JWKSURL:        env("MCP_AUTH_JWKS_URI", issuer+"/.well-known/jwks.json"),
		Issuer:         issuer,
		Audience:       resource,
		RequiredScopes: map[string]bool{"tools:read": true},
	}
	metadataURL := resource[:len(resource)-len("/mcp")] + "/.well-known/oauth-protected-resource/mcp"
	metadata := mcpauth.ProtectedResourceMetadataHandler(verifier, resource, issuer)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := mcpauth.TokenClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "missing verified claims", http.StatusInternalServerError)
			return
		}
		scopes := make([]string, 0, len(claims.Scopes))
		for scope := range claims.Scopes {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]string{"name": "go-mcp", "version": "0.3.0"},
				"subject":         claims.Subject,
				"scopes":          scopes,
			},
		})
	})
	mux := http.NewServeMux()
	mux.Handle("/.well-known/oauth-protected-resource", metadata)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", metadata)
	mux.Handle("/mcp", mcpauth.RequireToken(verifier, mcpauth.ResourceMetadata{URL: metadataURL}, handler))
	log.Printf("Go MCP server listening at %s", resource)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, mux))
}
