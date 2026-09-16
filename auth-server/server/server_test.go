package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	config := Config{Issuer: "http://localhost:8080", Resource: "http://localhost:8081/mcp", AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, AuthorizationCodeTTL: time.Minute, AllowedScopes: []string{"tools:read"}, RegistrationEnabled: true, LocalDevelopment: true, LocalSubject: "test-user"}
	instance, err := NewServer(config, NewMemoryStore(), LocalIdentityProvider{Subject: "test-user"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Store.SaveClient(Client{ID: "client", RedirectURIs: []string{"http://localhost:9999/callback"}, TokenEndpointAuth: "none"}); err != nil {
		t.Fatal(err)
	}
	return instance
}

func TestMetadataAndJWKS(t *testing.T) {
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/jwks.json"} {
		recorder := httptest.NewRecorder()
		testServer(t).Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, recorder.Code)
		}
	}
}

func TestAuthorizationCodePKCE(t *testing.T) {
	instance := testServer(t)
	verifier := "test-verifier-1234567890"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp&scope=tools%3Aread&state=state&approve=true", nil)
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status: %d, body: %s", recorder.Code, recorder.Body.String())
	}
	code := recorder.Header().Get("Location")
	parsed, _ := url.Parse(code)
	authorizationCode := parsed.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {authorizationCode}, "redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {verifier}, "resource": {"http://localhost:8081/mcp"}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(tokenRecorder, tokenRequest)
	if tokenRecorder.Code != http.StatusOK {
		t.Fatalf("token status: %d, body: %s", tokenRecorder.Code, tokenRecorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(tokenRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["access_token"] == nil {
		t.Fatal("missing access token")
	}
}

func TestBadPKCERejected(t *testing.T) {
	instance := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&code_challenge=bad&code_challenge_method=S256&resource=http%3A%2F%2Flocalhost%3A8081%2Fmcp&approve=true", nil)
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	parsed, _ := url.Parse(recorder.Header().Get("Location"))
	code := parsed.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {code}, "redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {"wrong"}}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(tokenRecorder, tokenRequest)
	if tokenRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", tokenRecorder.Code)
	}
}

func TestAuditRedactsSecrets(t *testing.T) {
	var output bytes.Buffer
	logger := NewAuditLogger(&output)
	logger.Event("token_issued", "success", map[string]any{"client_id": "client", "access_token": "secret-token", "client_secret": "secret-value"})
	if strings.Contains(output.String(), "secret-token") || strings.Contains(output.String(), "secret-value") {
		t.Fatal("audit output contained a secret")
	}
}
