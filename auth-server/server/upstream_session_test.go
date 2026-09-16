package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestUpstreamSessionExchangerReturnsStoredSessionWhenValid(t *testing.T) {
	store := NewMemoryStore()
	if err := store.SaveUpstreamSession("user-1", UpstreamSession{
		AccessToken: "stored-access-token", TokenType: "Bearer",
		ExpiresAt: time.Now().Add(time.Hour), Scope: []string{"sql"},
	}); err != nil {
		t.Fatal(err)
	}
	exchanger, err := NewUpstreamSessionExchanger(store, ConnectorConfig{TokenEndpointAuthMethod: "none"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := exchanger.Exchange(context.Background(), ExchangeRequest{Subject: "user-1"})
	if err != nil || response.AccessToken != "stored-access-token" {
		t.Fatalf("exchange: %v, %+v", err, response)
	}
}

func TestUpstreamSessionExchangerRejectsMissingSubject(t *testing.T) {
	exchanger, err := NewUpstreamSessionExchanger(NewMemoryStore(), ConnectorConfig{TokenEndpointAuthMethod: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchanger.Exchange(context.Background(), ExchangeRequest{}); err == nil {
		t.Fatal("expected a missing subject to be rejected")
	}
}

func TestUpstreamSessionExchangerErrorsWithNoStoredSession(t *testing.T) {
	exchanger, err := NewUpstreamSessionExchanger(NewMemoryStore(), ConnectorConfig{TokenEndpointAuthMethod: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchanger.Exchange(context.Background(), ExchangeRequest{Subject: "no-such-user"}); err == nil {
		t.Fatal("expected an unknown subject to be rejected")
	}
}

func TestUpstreamSessionExchangerErrorsWhenExpiredWithNoRefreshToken(t *testing.T) {
	store := NewMemoryStore()
	if err := store.SaveUpstreamSession("user-1", UpstreamSession{
		AccessToken: "stale", ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	exchanger, err := NewUpstreamSessionExchanger(store, ConnectorConfig{TokenEndpointAuthMethod: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchanger.Exchange(context.Background(), ExchangeRequest{Subject: "user-1"}); err == nil {
		t.Fatal("expected an expired session with no refresh token to be rejected")
	}
}

func TestUpstreamSessionExchangerRefreshesExpiredSession(t *testing.T) {
	var gotForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotForm = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "refreshed-access-token", "refresh_token": "rotated-refresh-token",
			"token_type": "Bearer", "expires_in": 300,
		})
	}))
	defer server.Close()

	store := NewMemoryStore()
	if err := store.SaveUpstreamSession("user-1", UpstreamSession{
		AccessToken: "stale-access-token", RefreshToken: "old-refresh-token",
		ExpiresAt: time.Now().Add(-time.Minute), Scope: []string{"sql"},
	}); err != nil {
		t.Fatal(err)
	}
	exchanger, err := NewUpstreamSessionExchanger(store, ConnectorConfig{TokenEndpoint: server.URL, TokenEndpointAuthMethod: "none", ClientID: "test-client"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := exchanger.Exchange(context.Background(), ExchangeRequest{Subject: "user-1"})
	if err != nil || response.AccessToken != "refreshed-access-token" {
		t.Fatalf("exchange: %v, %+v", err, response)
	}
	if gotForm.Get("grant_type") != "refresh_token" || gotForm.Get("refresh_token") != "old-refresh-token" {
		t.Fatalf("unexpected refresh request: %v", gotForm)
	}
	persisted, err := store.GetUpstreamSession("user-1")
	if err != nil || persisted.AccessToken != "refreshed-access-token" || persisted.RefreshToken != "rotated-refresh-token" {
		t.Fatalf("refreshed session was not persisted: %v, %+v", err, persisted)
	}
}

func TestUpstreamSessionExchangerKeepsRefreshTokenWhenNotRotated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "refreshed-access-token", "expires_in": 300})
	}))
	defer server.Close()

	store := NewMemoryStore()
	if err := store.SaveUpstreamSession("user-1", UpstreamSession{
		AccessToken: "stale", RefreshToken: "keep-me", ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	exchanger, err := NewUpstreamSessionExchanger(store, ConnectorConfig{TokenEndpoint: server.URL, TokenEndpointAuthMethod: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchanger.Exchange(context.Background(), ExchangeRequest{Subject: "user-1"}); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.GetUpstreamSession("user-1")
	if err != nil || persisted.RefreshToken != "keep-me" {
		t.Fatalf("expected the existing refresh token to be kept when the provider doesn't rotate it: %v, %+v", err, persisted)
	}
}
