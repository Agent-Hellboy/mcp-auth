package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigSecureDefaults(t *testing.T) {
	for _, name := range []string{
		"MCP_AUTH_LOCAL_DEVELOPMENT", "MCP_AUTH_REQUIRE_HTTPS", "MCP_AUTH_REGISTRATION_ENABLED",
	} {
		t.Setenv(name, "")
	}
	config := ConfigFromEnv()
	if config.LocalDevelopment || !config.RequireHTTPS || config.RegistrationEnabled {
		t.Fatalf("insecure defaults: %+v", config)
	}
}

func TestConfigRejectsUnsafeDeployment(t *testing.T) {
	config := Config{Issuer: "https://auth.example.com", Resource: "https://mcp.example.com", LocalDevelopment: true, RequireHTTPS: true}
	if err := config.Validate(); err == nil {
		t.Fatal("expected non-loopback local issuer to be rejected")
	}
	config = Config{Issuer: "https://auth.example.com", Resource: "https://mcp.example.com", RequireHTTPS: true, StoreBackend: "memory"}
	if err := config.Validate(); err == nil {
		t.Fatal("expected production memory store to be rejected")
	}
}

func TestConnectorLoaderRejectsLiteralSecretAndAcceptsProviderConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(path, []byte(`{"bad":{"client_secret":"do-not-store"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConnectors(path); err == nil {
		t.Fatal("expected literal client secret to be rejected")
	}
	valid := `{"provider":{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/authorize","token_endpoint":"https://idp.example.com/token","jwks_uri":"https://idp.example.com/jwks","client_id":"client","scopes":["openid"],"mcp_scopes":["tools:read"],"exchange_client_id":"exchange","token_endpoint_auth_method":"none","allowed_client_redirect_uris":["https://client.example.com/callback"]}}`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	connectors, err := LoadConnectors(path)
	if err != nil || connectors["provider"].Issuer != "https://idp.example.com" {
		t.Fatalf("load connector: %v", err)
	}
}

func TestSQLiteStorePersistsAndRotatesRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	client := Client{ID: "client", RedirectURIs: []string{"https://client.example.com/callback"}, TokenEndpointAuth: "none"}
	if err := store.SaveClient(client); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetClient(client.ID); err != nil {
		t.Fatal(err)
	}
	refresh := RefreshToken{ValueHash: HashSecret("refresh"), ClientID: client.ID, Subject: "user", Scope: []string{"tools:read"}, Resource: "https://mcp.example.com", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.SaveRefreshToken(refresh); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefreshToken("refresh", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefreshToken("refresh", time.Now()); !errors.Is(err, ErrAlreadyUsed) {
		t.Fatalf("expected reuse rejection, got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.GetClient(client.ID); err != nil {
		t.Fatalf("client did not persist: %v", err)
	}
}

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
