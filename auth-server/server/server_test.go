package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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

func TestLoadResourceClientsValidatesPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resource-clients.json")
	if err := os.WriteFile(path, []byte(`[{"client_id":"bad","public_key_pem":"not-a-key"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResourceClients(path); err == nil {
		t.Fatal("expected an invalid public key to be rejected")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	valid := fmt.Sprintf(`[{"client_id":"resource-server","name":"databricks-mcp","public_key_pem":%q}]`, string(publicPEM))
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	clients, err := LoadResourceClients(path)
	if err != nil || len(clients) != 1 || clients[0].ClientID != "resource-server" {
		t.Fatalf("load resource clients: %v, %+v", err, clients)
	}
}

func TestPrivateKeyJWTClientCannotBypassAssertionViaFormClientID(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	registerResourceClient(t, instance, "resource-server")
	// No client_assertion at all: a private_key_jwt client has no secret, so
	// it must not fall through the "no secret configured" bypass meant for
	// TokenEndpointAuth "none" DCR clients.
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"whatever"}, "audience": {"https://downstream.example.com"}, "client_id": {"resource-server"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected a private_key_jwt client without an assertion to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTokenExchangeRequiresClientAuthentication(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"whatever"}, "audience": {"https://downstream.example.com"}}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated token exchange to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func registerResourceClient(t *testing.T, instance *Server, clientID string) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := instance.Store.SaveClient(Client{ID: clientID, TokenEndpointAuth: "private_key_jwt", PublicKeyPEM: string(publicPEM)}); err != nil {
		t.Fatal(err)
	}
	return key
}

func signTestClientAssertion(t *testing.T, key *rsa.PrivateKey, clientID, audience string) string {
	t.Helper()
	now := time.Now().UTC()
	header := map[string]any{"typ": "JWT", "alg": "RS256"}
	claims := map[string]any{"iss": clientID, "sub": clientID, "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": randomID()}
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

func exchangeForm(subjectToken, clientID, assertion string) url.Values {
	return url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":         {subjectToken},
		"audience":              {"https://downstream.example.com"},
		"client_id":             {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
}

func TestTokenExchangeWithValidPrivateKeyJWTSucceedsOnce(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	key := registerResourceClient(t, instance, "resource-server")
	subjectToken, err := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "user-1", instance.Config.Resource, []string{"tools:read"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form := exchangeForm(subjectToken, "resource-server", assertion)

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected exchange to succeed, got %d: %s", recorder.Code, recorder.Body.String())
	}

	replay := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected replayed client assertion to be rejected, got %d: %s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func TestTokenExchangeRejectsForeignSubjectToken(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	key := registerResourceClient(t, instance, "resource-server")
	assertion := signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form := exchangeForm("not-a-token-this-server-issued", "resource-server", assertion)

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected a fabricated subject_token to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestTokenExchangeRejectsSubjectTokenForWrongResource(t *testing.T) {
	instance := testServer(t)
	instance.TokenExchanger = LocalTokenExchanger{Issuer: instance.Config.Issuer, KeyProvider: instance.KeyProvider, TTL: time.Minute}
	key := registerResourceClient(t, instance, "resource-server")
	subjectToken, err := instance.KeyProvider.Sign(context.Background(), instance.Config.Issuer, "user-1", "http://some-other-resource/mcp", []string{"tools:read"}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	assertion := signTestClientAssertion(t, key, "resource-server", instance.Config.Issuer+"/token")
	form := exchangeForm(subjectToken, "resource-server", assertion)

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected a subject_token minted for a different resource to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
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
