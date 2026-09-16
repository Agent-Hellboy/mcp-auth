package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConnectorsFillsMissingEndpointsViaDiscovery(t *testing.T) {
	var discoveryRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		discoveryRequests++
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "http://discovered.example.com/authorize",
			"token_endpoint":         "http://discovered.example.com/token",
			"jwks_uri":               "http://discovered.example.com/jwks",
			"userinfo_endpoint":      "http://discovered.example.com/userinfo",
		})
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "connectors.json")
	body := fmt.Sprintf(`{"provider":{"issuer":%q,"client_id":"client","exchange_client_id":"exchange","token_endpoint_auth_method":"none","mcp_scopes":["tools:read"]}}`, server.URL)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	connectors, err := LoadConnectorsWithOptions(path, true)
	if err != nil {
		t.Fatalf("load connectors: %v", err)
	}
	connector := connectors["provider"]
	if connector.AuthorizationEndpoint != "http://discovered.example.com/authorize" ||
		connector.TokenEndpoint != "http://discovered.example.com/token" ||
		connector.JWKSURI != "http://discovered.example.com/jwks" ||
		connector.UserinfoEndpoint != "http://discovered.example.com/userinfo" {
		t.Fatalf("endpoints were not filled in from discovery: %+v", connector)
	}
	if discoveryRequests != 1 {
		t.Fatalf("expected exactly one discovery request, got %d", discoveryRequests)
	}
}

func TestLoadConnectorsSkipsDiscoveryWhenFullySpecified(t *testing.T) {
	// issuer points at a host that would fail if dialed, so if discovery
	// were incorrectly triggered for a fully-specified connector, this load
	// would fail instead of succeeding.
	const unreachableIssuer = "http://127.0.0.1:1"
	path := filepath.Join(t.TempDir(), "connectors.json")
	body := fmt.Sprintf(`{"provider":{
		"issuer":%q,
		"authorization_endpoint":"http://idp.example.com/authorize",
		"token_endpoint":"http://idp.example.com/token",
		"jwks_uri":"http://idp.example.com/jwks",
		"client_id":"client","exchange_client_id":"exchange",
		"token_endpoint_auth_method":"none","mcp_scopes":["tools:read"]
	}}`, unreachableIssuer)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	connectors, err := LoadConnectorsWithOptions(path, true)
	if err != nil {
		t.Fatalf("expected a fully-specified connector to load without attempting discovery: %v", err)
	}
	if connectors["provider"].AuthorizationEndpoint != "http://idp.example.com/authorize" {
		t.Fatalf("unexpected connector: %+v", connectors["provider"])
	}
}

func TestLoadConnectorsReportsDiscoveryFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connectors.json")
	body := `{"provider":{"issuer":"http://127.0.0.1:1","client_id":"client","exchange_client_id":"exchange","token_endpoint_auth_method":"none","mcp_scopes":["tools:read"]}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConnectorsWithOptions(path, true); err == nil {
		t.Fatal("expected an unreachable issuer with missing endpoints to fail discovery")
	}
}
