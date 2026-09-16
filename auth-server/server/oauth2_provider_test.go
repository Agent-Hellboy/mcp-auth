package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// plainOAuth2Provider stands in for a GitHub-style provider: it issues an
// access token and exposes identity through userinfo, and never returns an
// id_token because nothing ever asked it for one.
func plainOAuth2Provider(t *testing.T, userinfo map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-access-token", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upstream-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(userinfo)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func plainOAuth2Connector(server *httptest.Server) ConnectorConfig {
	return ConnectorConfig{
		Issuer:                  server.URL,
		AuthorizationEndpoint:   server.URL + "/authorize",
		TokenEndpoint:           server.URL + "/token",
		JWKSURI:                 server.URL + "/jwks",
		UserinfoEndpoint:        server.URL + "/userinfo",
		TokenEndpointAuthMethod: "none",
		Scopes:                  []string{"read:user"},
		IdentityClaims:          []string{"login", "email"},
	}
}

func completeCallback(t *testing.T, provider *OIDCIdentityProvider) (Identity, error) {
	t.Helper()
	return provider.Complete(context.Background(), IdentityCallback{
		Code: "auth-code", RedirectURI: "https://mcp-auth.example.com/identity/callback",
		State: "state-1", Nonce: "n", CodeVerifier: "verifier",
	})
}

func TestPlainOAuth2ProviderResolvesIdentityFromUserinfo(t *testing.T) {
	server := plainOAuth2Provider(t, map[string]any{"login": "octocat"})
	provider := &OIDCIdentityProvider{
		Connector: plainOAuth2Connector(server),
		Client:    http.DefaultClient,
		ClientID:  "oauth2-client",
	}

	identity, err := completeCallback(t, provider)
	if err != nil {
		t.Fatalf("expected a provider that issues no id_token to work: %v", err)
	}
	if identity.Subject != "octocat" {
		t.Fatalf("unexpected subject: %q", identity.Subject)
	}
	if identity.UpstreamSession == nil || identity.UpstreamSession.AccessToken != "upstream-access-token" {
		t.Fatalf("upstream session was not captured: %+v", identity.UpstreamSession)
	}
}

func TestOIDCConnectorStillRequiresIDToken(t *testing.T) {
	// Same provider, but this connector asks for "openid" — so a missing
	// id_token is a real fault (a misconfigured scope list, say), not a cue to
	// silently accept userinfo with no ID token verification.
	server := plainOAuth2Provider(t, map[string]any{"login": "octocat"})
	connector := plainOAuth2Connector(server)
	connector.Scopes = []string{"openid", "read:user"}
	provider := &OIDCIdentityProvider{Connector: connector, Client: http.DefaultClient, ClientID: "oidc-client"}

	if _, err := completeCallback(t, provider); err == nil {
		t.Fatal("expected a connector requesting openid to reject a response with no id_token")
	}
}

func TestConnectorWithNoScopesRequiresIDToken(t *testing.T) {
	// Begin() sends "openid" when no scopes are configured, so an empty list
	// has to count as OIDC here too or the two would disagree.
	if !(ConnectorConfig{}).requiresIDToken() {
		t.Fatal("a connector with no configured scopes must still require an id_token")
	}
}

func TestPlainOAuth2ProviderWithoutUserinfoIsRejected(t *testing.T) {
	server := plainOAuth2Provider(t, map[string]any{"login": "octocat"})
	connector := plainOAuth2Connector(server)
	connector.UserinfoEndpoint = ""
	provider := &OIDCIdentityProvider{Connector: connector, Client: http.DefaultClient, ClientID: "oauth2-client"}

	if _, err := completeCallback(t, provider); err == nil {
		t.Fatal("expected no id_token and no userinfo_endpoint to be rejected rather than yielding an empty subject")
	}
}
