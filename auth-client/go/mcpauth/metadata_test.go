package mcpauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProtectedResourceMetadataAdvertisesRequiredScopes(t *testing.T) {
	verifier := &JWTVerifier{RequiredScopes: map[string]bool{"tools:write": true, "tools:read": true}}
	metadata := NewProtectedResourceMetadata(verifier, "https://mcp.example.com/ping/mcp", "https://auth.example.com/mcp-auth")

	if metadata.Resource != "https://mcp.example.com/ping/mcp" {
		t.Fatalf("resource = %q", metadata.Resource)
	}
	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://auth.example.com/mcp-auth" {
		t.Fatalf("authorization_servers = %v", metadata.AuthorizationServers)
	}
	// Sorted, so the document is byte-identical between requests.
	if len(metadata.ScopesSupported) != 2 || metadata.ScopesSupported[0] != "tools:read" || metadata.ScopesSupported[1] != "tools:write" {
		t.Fatalf("scopes_supported = %v, want [tools:read tools:write]", metadata.ScopesSupported)
	}
}

// A resource server that enforces no scope must not advertise an empty list;
// RFC 9728 says omit the member instead.
func TestProtectedResourceMetadataOmitsEmptyScopes(t *testing.T) {
	for name, verifier := range map[string]*JWTVerifier{
		"nil verifier": nil,
		"no scopes":    {RequiredScopes: map[string]bool{}},
	} {
		t.Run(name, func(t *testing.T) {
			body := serveMetadata(t, verifier)
			if _, present := body["scopes_supported"]; present {
				t.Fatalf("scopes_supported present for %s: %v", name, body)
			}
		})
	}
}

// The advertised scopes must match what RequireToken enforces, so a client that
// reads the document and asks for those scopes is never rejected for scope.
func TestProtectedResourceMetadataMatchesEnforcedScopes(t *testing.T) {
	verifier := &JWTVerifier{RequiredScopes: map[string]bool{"tools:read": true}}
	body := serveMetadata(t, verifier)

	advertised, ok := body["scopes_supported"].([]any)
	if !ok || len(advertised) != 1 || advertised[0] != "tools:read" {
		t.Fatalf("scopes_supported = %v", body["scopes_supported"])
	}
	if got := requiredScopes(verifier); len(got) != 1 || got[0] != "tools:read" {
		t.Fatalf("enforced scopes = %v, advertised %v", got, advertised)
	}
}

func serveMetadata(t *testing.T, verifier *JWTVerifier) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	ProtectedResourceMetadataHandler(verifier, "https://mcp.example.com/ping/mcp", "https://auth.example.com/mcp-auth").
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if ct := recorder.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}
