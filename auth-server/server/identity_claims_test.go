package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveIdentityClaimFallsBackThroughList(t *testing.T) {
	provider := &OIDCIdentityProvider{Connector: ConnectorConfig{IdentityClaims: []string{"sub", "email"}}}
	subject, claims, err := provider.resolveIdentityClaim(context.Background(), map[string]any{"email": "user@example.com"}, nil)
	if err != nil || subject != "user@example.com" {
		t.Fatalf("expected fallback to email: %v, %q", err, subject)
	}
	if claims["email"] != "user@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestResolveIdentityClaimPrefersEarlierEntryWhenBothPresent(t *testing.T) {
	provider := &OIDCIdentityProvider{Connector: ConnectorConfig{IdentityClaims: []string{"sub", "email"}}}
	subject, _, err := provider.resolveIdentityClaim(context.Background(), map[string]any{"sub": "user-1", "email": "user@example.com"}, nil)
	if err != nil || subject != "user-1" {
		t.Fatalf("expected sub to be preferred: %v, %q", err, subject)
	}
}

func TestResolveIdentityClaimDoesNotCallUserinfoWhenAlreadyResolvable(t *testing.T) {
	var requests int
	userinfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"email": "should-not-be-fetched@example.com"})
	}))
	defer userinfoServer.Close()

	provider := &OIDCIdentityProvider{Connector: ConnectorConfig{UserinfoEndpoint: userinfoServer.URL}, Client: http.DefaultClient}
	subject, _, err := provider.resolveIdentityClaim(context.Background(), map[string]any{"sub": "user-1"}, &UpstreamSession{AccessToken: "token"})
	if err != nil || subject != "user-1" {
		t.Fatalf("resolveIdentityClaim: %v, %q", err, subject)
	}
	if requests != 0 {
		t.Fatalf("expected userinfo not to be called when sub is already present, got %d requests", requests)
	}
}

func TestResolveIdentityClaimCallsUserinfoWhenNoClaimPresent(t *testing.T) {
	var gotAuth string
	userinfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"email": "user@example.com"})
	}))
	defer userinfoServer.Close()

	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{IdentityClaims: []string{"sub", "email"}, UserinfoEndpoint: userinfoServer.URL},
		Client:    http.DefaultClient,
	}
	subject, claims, err := provider.resolveIdentityClaim(context.Background(), map[string]any{"iss": "https://idp.example.com"}, &UpstreamSession{AccessToken: "upstream-token"})
	if err != nil || subject != "user@example.com" {
		t.Fatalf("resolveIdentityClaim: %v, %q", err, subject)
	}
	if gotAuth != "Bearer upstream-token" {
		t.Fatalf("expected the upstream access token as the userinfo bearer, got %q", gotAuth)
	}
	if claims["iss"] != "https://idp.example.com" {
		t.Fatalf("expected ID token claims to survive the merge: %+v", claims)
	}
}

func TestResolveIdentityClaimIDTokenClaimsWinOverUserinfo(t *testing.T) {
	userinfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"email": "userinfo-value@example.com", "sub": "userinfo-sub"})
	}))
	defer userinfoServer.Close()

	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{IdentityClaims: []string{"email"}, UserinfoEndpoint: userinfoServer.URL},
		Client:    http.DefaultClient,
	}
	// "email" isn't present in the ID token claims, so userinfo is called
	// and supplies it; "sub" IS present in the ID token and must not be
	// overwritten by userinfo's own (different) sub value.
	subject, claims, err := provider.resolveIdentityClaim(context.Background(), map[string]any{"sub": "id-token-sub"}, &UpstreamSession{AccessToken: "token"})
	if err != nil || subject != "userinfo-value@example.com" {
		t.Fatalf("resolveIdentityClaim: %v, %q", err, subject)
	}
	if claims["sub"] != "id-token-sub" {
		t.Fatalf("expected the ID token's sub to win over userinfo's, got %v", claims["sub"])
	}
}

func TestResolveIdentityClaimErrorsWithoutUserinfoEndpoint(t *testing.T) {
	provider := &OIDCIdentityProvider{Connector: ConnectorConfig{}}
	if _, _, err := provider.resolveIdentityClaim(context.Background(), map[string]any{"iss": "https://idp.example.com"}, nil); err == nil {
		t.Fatal("expected an error when no identity claim is present and no userinfo_endpoint is configured")
	}
}
