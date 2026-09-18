package mcpauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A path-mounted issuer served only at the OIDC-style suffix URL must still be
// discoverable: the RFC 8414 URL is tried first, and the suffix form is the
// fallback. Without the fallback this client cannot talk to any deployment
// that predates RFC 8414 awareness on the server side.
func TestDiscoverAuthorizationServerFallsBackToSuffixForm(t *testing.T) {
	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		if r.URL.Path != "/mcp-auth/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":"%s/mcp-auth/authorize"}`, srvIssuer(r), "http://"+r.Host)
	}))
	defer srv.Close()

	metadata, err := DiscoverAuthorizationServer(srv.Client(), srv.URL+"/mcp-auth")
	if err != nil {
		t.Fatalf("discovery failed: %v (tried %v)", err, requested)
	}
	if metadata.Issuer != srv.URL+"/mcp-auth" {
		t.Fatalf("issuer = %q", metadata.Issuer)
	}
	if requested[0] != "/.well-known/oauth-authorization-server/mcp-auth" {
		t.Fatalf("RFC 8414 URL should be tried first, got %q", requested[0])
	}
}

// The RFC 8414 URL is preferred when the server offers both.
func TestDiscoverAuthorizationServerPrefersRFC8414(t *testing.T) {
	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q}`, srvIssuer(r))
	}))
	defer srv.Close()

	if _, err := DiscoverAuthorizationServer(srv.Client(), srv.URL+"/mcp-auth"); err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	if len(requested) != 1 || requested[0] != "/.well-known/oauth-authorization-server/mcp-auth" {
		t.Fatalf("expected exactly the RFC 8414 URL, got %v", requested)
	}
}

func srvIssuer(r *http.Request) string {
	return "http://" + r.Host + "/mcp-auth"
}
