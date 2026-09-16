package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func jwkFor(key *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signTestIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": kid}
	headEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(header))
	claimEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	message := []byte(headEncoded + "." + claimEncoded)
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return string(message) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCCompleteCapturesUpstreamSession(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwkFor(&key.PublicKey, "test-key")}})
	}))
	defer jwksServer.Close()

	const issuer = "https://upstream.example.com"
	const clientID = "test-client"
	now := time.Now().UTC()
	idToken := signTestIDToken(t, key, "test-key", map[string]any{
		"iss": issuer, "sub": "user-1", "aud": clientID, "nonce": "expected-nonce",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})

	var tokenServer *httptest.Server
	tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token": idToken, "access_token": "upstream-access-token", "refresh_token": "upstream-refresh-token",
			"token_type": "Bearer", "expires_in": 300, "scope": "sql unity-catalog",
		})
	}))
	defer func() { tokenServer.Close() }()

	provider := &OIDCIdentityProvider{
		Connector: ConnectorConfig{Issuer: issuer, TokenEndpoint: tokenServer.URL, JWKSURI: jwksServer.URL, TokenEndpointAuthMethod: "none"},
		Client:    http.DefaultClient,
		ClientID:  clientID,
	}
	identity, err := provider.Complete(context.Background(), IdentityCallback{
		Code: "auth-code", RedirectURI: "https://mcp-auth.example.com/identity/callback", State: "state-1",
		Nonce: "expected-nonce", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if identity.Subject != "user-1" {
		t.Fatalf("unexpected subject: %q", identity.Subject)
	}
	if identity.UpstreamSession == nil {
		t.Fatal("expected Complete to capture an upstream session")
	}
	session := *identity.UpstreamSession
	if session.AccessToken != "upstream-access-token" || session.RefreshToken != "upstream-refresh-token" {
		t.Fatalf("unexpected upstream session: %+v", session)
	}
	if len(session.Scope) != 2 || session.Scope[0] != "sql" || session.Scope[1] != "unity-catalog" {
		t.Fatalf("unexpected upstream session scope: %+v", session.Scope)
	}
	if session.ExpiresAt.Before(time.Now().Add(4*time.Minute)) || session.ExpiresAt.After(time.Now().Add(6*time.Minute)) {
		t.Fatalf("unexpected upstream session expiry: %v", session.ExpiresAt)
	}
}

func TestJWKSCacheDoesNotRefetchWithinTTL(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwkFor(&key.PublicKey, "kid-1")}})
	}))
	defer server.Close()

	var cache jwksCache
	for range 3 {
		resolved, err := cache.resolve(context.Background(), server.Client(), server.URL, "kid-1")
		rsaKey, ok := resolved.(*rsa.PublicKey)
		if err != nil || !ok || rsaKey.N.Cmp(key.PublicKey.N) != 0 {
			t.Fatalf("resolve: %v", err)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected exactly one JWKS fetch within the cache TTL, got %d", got)
	}
}

func TestJWKSCacheRefreshesOnUnknownKid(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests int32
	var rotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		keys := []any{jwkFor(&keyA.PublicKey, "kid-a")}
		if rotated.Load() {
			keys = append(keys, jwkFor(&keyB.PublicKey, "kid-b"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer server.Close()

	var cache jwksCache
	if _, err := cache.resolve(context.Background(), server.Client(), server.URL, "kid-a"); err != nil {
		t.Fatalf("initial resolve: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected one fetch, got %d", got)
	}

	rotated.Store(true)
	resolved, err := cache.resolve(context.Background(), server.Client(), server.URL, "kid-b")
	rsaKey, ok := resolved.(*rsa.PublicKey)
	if err != nil || !ok || rsaKey.N.Cmp(keyB.PublicKey.N) != 0 {
		t.Fatalf("expected an unknown kid to trigger a refresh: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("expected a second fetch after an unknown kid, got %d", got)
	}
}

func TestJWKSCacheTTLHonorsCacheControl(t *testing.T) {
	cases := map[string]time.Duration{
		"max-age=120":          120 * time.Second,
		"public, max-age=30":   30 * time.Second,
		"no-cache":             defaultJWKSCacheTTL,
		"":                     defaultJWKSCacheTTL,
		"max-age=not-a-number": defaultJWKSCacheTTL,
		"max-age=0":            defaultJWKSCacheTTL,
		"max-age=-5":           defaultJWKSCacheTTL,
	}
	for header, want := range cases {
		if got := jwksCacheTTL(header); got != want {
			t.Errorf("jwksCacheTTL(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestRSAExponentRejectsOversizedOrInvalidValues(t *testing.T) {
	if _, err := rsaExponent(make([]byte, 5)); err == nil {
		t.Fatal("expected an oversized exponent to be rejected")
	}
	if _, err := rsaExponent(nil); err == nil {
		t.Fatal("expected an empty exponent to be rejected")
	}
	if _, err := rsaExponent([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected a zero exponent to be rejected")
	}
	exponent, err := rsaExponent([]byte{0x01, 0x00, 0x01}) // 65537, the common case
	if err != nil || exponent != 65537 {
		t.Fatalf("rsaExponent(65537): got (%d, %v)", exponent, err)
	}
}

func TestValidExpiryAllowsClockSkew(t *testing.T) {
	justExpired := float64(time.Now().Add(-30 * time.Second).Unix())
	if !validExpiry(justExpired) {
		t.Fatal("expected an expiry just past now to be tolerated within clock skew")
	}
	longExpired := float64(time.Now().Add(-10 * time.Minute).Unix())
	if validExpiry(longExpired) {
		t.Fatal("expected an expiry well in the past to be rejected")
	}
}

func TestValidIssuedAtAndNotBefore(t *testing.T) {
	if !validIssuedAt(float64(time.Now().Unix())) {
		t.Fatal("expected an iat of now to be valid")
	}
	if validIssuedAt(float64(time.Now().Add(10 * time.Minute).Unix())) {
		t.Fatal("expected an iat far in the future to be rejected")
	}
	if !validNotBefore(nil) {
		t.Fatal("expected a missing nbf to be treated as valid")
	}
	if validNotBefore(float64(time.Now().Add(10 * time.Minute).Unix())) {
		t.Fatal("expected an nbf far in the future to be rejected")
	}
}
