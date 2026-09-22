package mcpauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func addCall(calls *int32) int32   { return atomic.AddInt32(calls, 1) }
func loadCalls(calls *int32) int32 { return atomic.LoadInt32(calls) }

func signedToken(t *testing.T, key *rsa.PrivateKey, exp int64, audience string) string {
	t.Helper()
	header := b64JSON(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test"})
	payload := b64JSON(map[string]any{"iss": "https://auth.example.com", "sub": "user", "aud": audience, "exp": exp, "scope": "tools:read"})
	message := header + "." + payload
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestJWTVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := key.PublicKey
	verifier := JWTVerifier{Issuer: "https://auth.example.com", Audience: "https://mcp.example.com", RequiredScopes: map[string]bool{"tools:read": true}, JWKSCacheTTL: time.Minute, keys: map[string]*rsa.PublicKey{"test": &public}, loadedAt: time.Now()}
	claims, err := verifier.Verify(signedToken(t, key, time.Now().Add(time.Minute).Unix(), "https://mcp.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user" {
		t.Fatalf("subject=%s", claims.Subject)
	}
	if _, err := verifier.Verify(signedToken(t, key, time.Now().Add(time.Minute).Unix(), "https://other.example.com")); err == nil {
		t.Fatal("expected audience rejection")
	}
}

func TestTokenCacheBoundsAndExpiry(t *testing.T) {
	cache := NewTokenCache(1, time.Second)
	cache.Put("a", CachedToken{AccessToken: "one", ExpiresAt: time.Now().Add(time.Minute)})
	cache.Put("b", CachedToken{AccessToken: "two", ExpiresAt: time.Now().Add(time.Minute)})
	if cache.Len() != 1 {
		t.Fatal("cache exceeded bound")
	}
	if _, ok := cache.Get("a"); ok {
		t.Fatal("old entry was not evicted")
	}
	if _, ok := cache.Get("b"); !ok {
		t.Fatal("new entry missing")
	}
}

func TestChallenge(t *testing.T) {
	challenge := ParseWWWAuthenticate(`Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource" scope="tools:read"`)
	if challenge.ResourceMetadata == "" || !strings.Contains(challenge.Scope, "tools:read") {
		t.Fatal("challenge did not parse")
	}
}

func TestUnauthorizedHeadersAreCommaSeparated(t *testing.T) {
	header := UnauthorizedHeaders("https://resource.example/.well-known/oauth-protected-resource", []string{"tools:read"})["WWW-Authenticate"]
	if !strings.Contains(header, `, scope="tools:read"`) {
		t.Fatalf("malformed challenge: %s", header)
	}
	if strings.Contains(header, `" scope=`) {
		t.Fatalf("challenge parameters are not comma-separated: %s", header)
	}
}

func TestTokenEndpointRequiresHTTPSUnlessOptedOut(t *testing.T) {
	client := &TokenExchangeClient{Endpoint: "http://127.0.0.1/token"}
	if _, err := client.Exchange("subject", "https://api.example.com", nil); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http endpoint error = %v", err)
	}
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		addCall(&calls)
		_, _ = w.Write([]byte(`{"access_token":"downstream","expires_in":300,"scope":"read"}`))
	}))
	defer server.Close()
	insecure := &TokenExchangeClient{Endpoint: server.URL, AllowInsecure: true, HTTPClient: server.Client(), Cache: NewTokenCache(4, time.Second)}
	first, err := insecure.Exchange("subject-token", "https://api.example.com", []string{"b", "a"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := insecure.Exchange("subject-token", "https://api.example.com", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if first.AccessToken != "downstream" || second.AccessToken != first.AccessToken || loadCalls(&calls) != 1 {
		t.Fatalf("exchange cache calls=%d token=%s", loadCalls(&calls), first.AccessToken)
	}
	key := exchangeCacheKey("subject-token", "https://api.example.com", []string{"b", "a"})
	if strings.Contains(key, "subject-token") || len(key) != 64 {
		t.Fatalf("cache key = %s", key)
	}
}

func TestUnknownKidDoesNotRefetchJWKS(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		addCall(&calls)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	header := b64JSON(map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "missing"})
	payload := b64JSON(map[string]any{"iss": "https://auth.example.com", "sub": "user", "aud": "https://mcp.example.com", "exp": time.Now().Add(time.Minute).Unix()})
	message := header + "." + payload
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	token := message + "." + base64.RawURLEncoding.EncodeToString(signature)
	verifier := JWTVerifier{JWKSURL: server.URL, Issuer: "https://auth.example.com", Audience: "https://mcp.example.com", HTTPClient: server.Client(), JWKSCacheTTL: time.Minute}
	for i := 0; i < 5; i++ {
		if _, err := verifier.Verify(token); err == nil {
			t.Fatal("expected unknown kid rejection")
		}
	}
	if loadCalls(&calls) != 1 {
		t.Fatalf("jwks fetches = %d, want 1", loadCalls(&calls))
	}
}

func TestJWKSSingleFlight(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := key.PublicKey
	body, err := json.Marshal(map[string]any{"keys": []map[string]string{rsaJWK(&public, "test")}})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if addCall(&calls) == 1 {
			once.Do(func() { close(started) })
			<-release
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	token := signedToken(t, key, time.Now().Add(time.Minute).Unix(), "https://mcp.example.com")
	verifier := JWTVerifier{JWKSURL: server.URL, Issuer: "https://auth.example.com", Audience: "https://mcp.example.com", HTTPClient: server.Client()}
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, verifyErr := verifier.Verify(token)
			errCh <- verifyErr
		}()
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("JWKS fetch did not start")
	}
	time.Sleep(50 * time.Millisecond)
	if loadCalls(&calls) != 1 {
		t.Fatalf("overlapping fetches = %d", loadCalls(&calls))
	}
	close(release)
	for i := 0; i < 2; i++ {
		if verifyErr := <-errCh; verifyErr != nil {
			t.Fatal(verifyErr)
		}
	}
	if loadCalls(&calls) != 1 {
		t.Fatalf("jwks fetches = %d, want 1", loadCalls(&calls))
	}
}

func TestJWKSRejectsBodyOverOneMiB(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := key.PublicKey
	document := map[string]any{"keys": []map[string]string{rsaJWK(&public, "test")}, "pad": strings.Repeat("a", 1<<20)}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 1<<20 {
		t.Fatalf("body = %d bytes", len(body))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	token := signedToken(t, key, time.Now().Add(time.Minute).Unix(), "https://mcp.example.com")
	verifier := JWTVerifier{JWKSURL: server.URL, Issuer: "https://auth.example.com", Audience: "https://mcp.example.com", HTTPClient: server.Client()}
	if _, err := verifier.Verify(token); err == nil {
		t.Fatal("expected oversized JWKS rejection")
	}
}

func rsaJWK(key *rsa.PublicKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigEndian(key.E)),
	}
}

func bigEndian(value int) []byte {
	raw := []byte{}
	for value > 0 {
		raw = append([]byte{byte(value)}, raw...)
		value >>= 8
	}
	if len(raw) == 0 {
		return []byte{0}
	}
	return raw
}

func TestDiscoveryInsertsWellKnownPathAndValidatesIssuer(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server/tenant1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"issuer":"` + server.URL + `/tenant1"}`))
	}))
	defer server.Close()
	issuer := server.URL + "/tenant1"
	metadata, err := DiscoverAuthorizationServer(server.Client(), issuer)
	if err != nil || metadata.Issuer != issuer {
		t.Fatalf("discovery failed: %+v, %v", metadata, err)
	}
}

// TestExchangeRefusesRedirect covers a 307 or 308 from the token endpoint.
// http.Client replays the body on those codes, so following a redirect to an
// http target would post the subject token and client assertion in cleartext.
func TestExchangeRefusesRedirect(t *testing.T) {
	var insecureHits int
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		insecureHits++
		_, _ = w.Write([]byte(`{"access_token":"leaked","expires_in":300}`))
	}))
	defer insecure.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, insecure.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := &TokenExchangeClient{Endpoint: redirector.URL, AllowInsecure: true}
	if _, err := client.Exchange("subject-token", "https://api.example.com", nil); err == nil {
		t.Fatal("Exchange followed a redirect instead of refusing it")
	}
	if insecureHits != 0 {
		t.Fatalf("redirect target received %d request(s); the body was replayed", insecureHits)
	}
}
