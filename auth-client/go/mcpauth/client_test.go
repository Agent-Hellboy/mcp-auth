package mcpauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
