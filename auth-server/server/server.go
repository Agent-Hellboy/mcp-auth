package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Server struct {
	Config           Config
	Store            Store
	Keys             *KeyManager
	KeyProvider      KeyProvider
	IdentityProvider IdentityProvider
	TokenExchanger   TokenExchanger
	Audit            *AuditLogger
	now              func() time.Time
}

type AuthorizationRequest struct {
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scope         []string `json:"scope"`
	State         string   `json:"state"`
	CodeChallenge string   `json:"code_challenge"`
	Resource      string   `json:"resource"`
	ResponseType  string   `json:"response_type"`
	Nonce         string   `json:"nonce"`
}

func NewServer(config Config, store Store, identityProvider IdentityProvider, exchanger TokenExchanger, auditWriter io.Writer) (*Server, error) {
	return NewServerWithKeyProvider(config, store, identityProvider, exchanger, nil, auditWriter)
}

func NewServerWithKeyProvider(config Config, store Store, identityProvider IdentityProvider, exchanger TokenExchanger, keyProvider KeyProvider, auditWriter io.Writer) (*Server, error) {
	if config.Issuer == "" || config.Resource == "" {
		return nil, errors.New("issuer and resource are required")
	}
	if store == nil {
		store = NewMemoryStore()
	}
	if identityProvider == nil {
		if !config.LocalDevelopment {
			return nil, errors.New("identity provider is required outside local development")
		}
		identityProvider = LocalIdentityProvider{Subject: config.LocalSubject}
	}
	if auditWriter == nil {
		auditWriter = io.Discard
	}
	if keyProvider == nil {
		keys, err := NewKeyManager(config.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		keyProvider = LocalKeyProvider{Keys: keys}
		return &Server{Config: config, Store: store, Keys: keys, KeyProvider: keyProvider, IdentityProvider: identityProvider, TokenExchanger: exchanger, Audit: NewAuditLogger(auditWriter), now: time.Now}, nil
	}
	return &Server{Config: config, Store: store, KeyProvider: keyProvider, IdentityProvider: identityProvider, TokenExchanger: exchanger, Audit: NewAuditLogger(auditWriter), now: time.Now}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authorizationMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.authorizationMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("GET /identity/callback", s.identityCallback)
	mux.HandleFunc("POST /authorize/consent", s.consent)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("POST /revoke", s.revoke)
	return s.cors(s.httpsOnly(mux))
}

func (s *Server) authorizationMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.Config.Issuer,
		"authorization_endpoint":                         s.Config.Issuer + "/authorize",
		"token_endpoint":                                 s.Config.Issuer + "/token",
		"registration_endpoint":                          s.Config.Issuer + "/register",
		"revocation_endpoint":                            s.Config.Issuer + "/revoke",
		"jwks_uri":                                       s.Config.Issuer + "/.well-known/jwks.json",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post", "private_key_jwt"},
		"scopes_supported":                               s.Config.AllowedScopes,
		"authorization_response_iss_parameter_supported": s.Config.AuthorizationResponseIssuer,
	})
}

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"resource": s.Config.Resource, "authorization_servers": []string{s.Config.Issuer}, "scopes_supported": s.Config.AllowedScopes})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	keys, err := s.KeyProvider.JWKS(r.Context())
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, keys)
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	request, err := s.parseAuthorizationRequest(r)
	if err != nil {
		oauthError(w, http.StatusBadRequest, err.Error())
		return
	}
	nonce := request.Nonce
	if nonce == "" {
		nonce = randomID()
	}
	consentID := randomID()
	if err := s.Store.SaveConsentRequest(ConsentRequest{ValueHash: HashSecret(consentID), Request: request, Nonce: nonce, ExpiresAt: s.now().Add(s.Config.AuthorizationCodeTTL)}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if s.Config.LocalDevelopment && r.URL.Query().Get("approve") == "true" {
		s.finishConsent(w, r, consentID, true)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentPage.Execute(w, map[string]any{"ID": consentID, "ClientID": request.ClientID, "Scopes": strings.Join(request.Scope, " ")})
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid consent form")
		return
	}
	s.finishConsent(w, r, r.FormValue("consent_id"), r.FormValue("decision") == "approve")
}

func (s *Server) finishConsent(w http.ResponseWriter, r *http.Request, consentID string, approved bool) {
	pending, err := s.Store.ConsumeConsentRequest(consentID, s.now())
	if err != nil {
		http.Error(w, "consent request expired", http.StatusBadRequest)
		return
	}
	request := pending.Request
	if !approved {
		redirectError(w, r, request, "access_denied", "consent was denied", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	if interactive, ok := s.IdentityProvider.(InteractiveIdentityProvider); ok {
		upstreamState := randomID()
		location, codeVerifier, err := interactive.Begin(r.Context(), IdentityRequest{
			ClientID: request.ClientID, Nonce: pending.Nonce, Resource: request.Resource, Scopes: request.Scope,
		}, upstreamState)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if err := s.Store.SaveConsentRequest(ConsentRequest{
			ValueHash: HashSecret(upstreamState), Request: request, Nonce: pending.Nonce,
			ExpiresAt: s.now().Add(s.Config.AuthorizationCodeTTL), CodeVerifier: codeVerifier,
		}); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	identity, err := s.IdentityProvider.Authenticate(r.Context(), IdentityRequest{ClientID: request.ClientID, Nonce: pending.Nonce, Resource: request.Resource, Scopes: request.Scope})
	if err != nil {
		redirectError(w, r, request, "access_denied", "identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	s.completeAuthorization(w, r, pending, identity)
}

func (s *Server) identityCallback(w http.ResponseWriter, r *http.Request) {
	interactive, ok := s.IdentityProvider.(InteractiveIdentityProvider)
	if !ok {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	pending, err := s.Store.ConsumeConsentRequest(state, s.now())
	if err != nil {
		http.Error(w, "identity state is invalid or expired", http.StatusBadRequest)
		return
	}
	if upstreamError := r.URL.Query().Get("error"); upstreamError != "" {
		redirectError(w, r, pending.Request, "access_denied", "upstream identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	identity, err := interactive.Complete(r.Context(), IdentityCallback{
		Code: r.URL.Query().Get("code"), RedirectURI: strings.TrimRight(s.Config.Issuer, "/") + "/identity/callback", Nonce: pending.Nonce, State: state,
		CodeVerifier: pending.CodeVerifier,
	})
	if err != nil {
		redirectError(w, r, pending.Request, "access_denied", "upstream identity authentication failed", s.Config.Issuer, s.Config.AuthorizationResponseIssuer)
		return
	}
	s.completeAuthorization(w, r, pending, identity)
}

func (s *Server) completeAuthorization(w http.ResponseWriter, r *http.Request, pending ConsentRequest, identity Identity) {
	request := pending.Request
	if identity.UpstreamSession != nil {
		if err := s.Store.SaveUpstreamSession(identity.Subject, *identity.UpstreamSession); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	code := randomID()
	if err := s.Store.SaveAuthorizationCode(AuthorizationCode{
		ValueHash: HashSecret(code), ClientID: request.ClientID, RedirectURI: request.RedirectURI,
		CodeChallenge: request.CodeChallenge, Scope: request.Scope, Resource: request.Resource,
		Subject: identity.Subject, Nonce: pending.Nonce, ExpiresAt: s.now().Add(s.Config.AuthorizationCodeTTL),
	}); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	s.Audit.Event("authorization_code_issued", "success", map[string]any{"client_id": request.ClientID, "subject": identity.Subject})
	location, _ := url.Parse(request.RedirectURI)
	query := location.Query()
	query.Set("code", code)
	if request.State != "" {
		query.Set("state", request.State)
	}
	if s.Config.AuthorizationResponseIssuer {
		query.Set("iss", s.Config.Issuer)
	}
	location.RawQuery = query.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) parseAuthorizationRequest(r *http.Request) (AuthorizationRequest, error) {
	q := r.URL.Query()
	request := AuthorizationRequest{ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), CodeChallenge: q.Get("code_challenge"), Resource: q.Get("resource"), ResponseType: q.Get("response_type"), Nonce: q.Get("nonce"), Scope: strings.Fields(q.Get("scope"))}
	client, err := s.Store.GetClient(request.ClientID)
	if err != nil {
		return request, fmt.Errorf("unknown client")
	}
	if request.ResponseType != "code" || request.CodeChallenge == "" || q.Get("code_challenge_method") != "S256" {
		return request, fmt.Errorf("code, response_type=code, and S256 PKCE are required")
	}
	if !contains(client.RedirectURIs, request.RedirectURI) || !validRedirect(request.RedirectURI) {
		return request, fmt.Errorf("redirect_uri is not registered")
	}
	if request.Resource == "" {
		request.Resource = s.Config.Resource
	}
	if request.Resource != s.Config.Resource {
		return request, fmt.Errorf("resource is not recognized")
	}
	for _, scope := range request.Scope {
		if !contains(s.Config.AllowedScopes, scope) {
			return request, fmt.Errorf("scope is not allowed")
		}
	}
	return request, nil
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid form")
		return
	}
	client, err := s.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.authorizationCodeToken(w, r)
	case "refresh_token":
		s.refreshTokenToken(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		s.exchange(w, r, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (s *Server) authorizationCodeToken(w http.ResponseWriter, r *http.Request) {
	code, err := s.Store.ConsumeAuthorizationCode(r.FormValue("code"), s.now())
	if err != nil || code.ClientID != r.FormValue("client_id") || code.RedirectURI != r.FormValue("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	verifier := r.FormValue("code_verifier")
	if !validPKCE(verifier, code.CodeChallenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	resource := r.FormValue("resource")
	if resource == "" {
		resource = code.Resource
	}
	if resource != code.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return
	}
	s.issueTokens(w, code.ClientID, code.Subject, code.Scope, resource)
}

func (s *Server) refreshTokenToken(w http.ResponseWriter, r *http.Request) {
	old := r.FormValue("refresh_token")
	token, err := s.Store.ConsumeRefreshToken(old, s.now())
	if err != nil {
		if errors.Is(err, ErrAlreadyUsed) {
			_ = s.Store.RevokeRefreshToken(old)
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if token.ClientID != r.FormValue("client_id") {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	s.issueTokens(w, token.ClientID, token.Subject, token.Scope, token.Resource)
}

func (s *Server) issueTokens(w http.ResponseWriter, clientID, subject string, scopes []string, resource string) {
	access, err := s.KeyProvider.Sign(context.Background(), s.Config.Issuer, subject, resource, scopes, s.Config.AccessTokenTTL, "")
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	refresh := randomID()
	_ = s.Store.SaveRefreshToken(RefreshToken{ValueHash: HashSecret(refresh), ClientID: clientID, Subject: subject, Scope: scopes, Resource: resource, ExpiresAt: s.now().Add(s.Config.RefreshTokenTTL)})
	s.Audit.Event("token_issued", "success", map[string]any{"client_id": clientID, "subject": subject, "resource": resource})
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(s.Config.AccessTokenTTL.Seconds()), "refresh_token": refresh, "scope": strings.Join(scopes, " ")})
}

// exchange handles RFC 8693 token exchange. The caller has already
// authenticated as client (see authenticateClient); this additionally
// verifies that subject_token is a still-valid access token this server
// itself issued for its own resource, rather than relaying an arbitrary
// caller-supplied string to the upstream provider.
func (s *Server) exchange(w http.ResponseWriter, r *http.Request, client Client) {
	if s.TokenExchanger == nil {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	subjectToken := r.FormValue("subject_token")
	subjectClaims, err := s.KeyProvider.Verify(r.Context(), subjectToken)
	if err != nil {
		s.Audit.Event("token_exchange", "failure", map[string]any{"client_id": client.ID, "audience": r.FormValue("audience"), "reason": "invalid_subject_token"})
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if subjectClaims["aud"] != s.Config.Resource {
		s.Audit.Event("token_exchange", "failure", map[string]any{"client_id": client.ID, "audience": r.FormValue("audience"), "reason": "subject_token_audience_mismatch"})
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	subject, _ := subjectClaims["sub"].(string)
	response, err := s.TokenExchanger.Exchange(r.Context(), ExchangeRequest{Subject: subject, SubjectToken: subjectToken, RequestedTokenType: r.FormValue("requested_token_type"), Audience: r.FormValue("audience"), Scope: strings.Fields(r.FormValue("scope"))})
	if err != nil {
		s.Audit.Event("token_exchange", "failure", map[string]any{"client_id": client.ID, "audience": r.FormValue("audience")})
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return
	}
	s.Audit.Event("token_exchange", "success", map[string]any{"client_id": client.ID, "subject": subjectClaims["sub"], "audience": r.FormValue("audience")})
	writeJSON(w, http.StatusOK, map[string]any{"access_token": response.AccessToken, "token_type": response.TokenType, "expires_in": response.ExpiresIn, "scope": response.Scope})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.Config.RegistrationEnabled {
		oauthError(w, http.StatusNotFound, "registration_disabled")
		return
	}
	var input struct {
		ClientName        string   `json:"client_name"`
		RedirectURIs      []string `json:"redirect_uris"`
		TokenEndpointAuth string   `json:"token_endpoint_auth_method"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || len(input.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	for _, redirectURI := range input.RedirectURIs {
		if !validRedirect(redirectURI) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri")
			return
		}
		if len(s.Config.AllowedClientRedirectURIs) > 0 && !contains(s.Config.AllowedClientRedirectURIs, redirectURI) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri")
			return
		}
	}
	clientID := "mcp_" + randomID()
	client := Client{ID: clientID, Name: input.ClientName, RedirectURIs: input.RedirectURIs, TokenEndpointAuth: input.TokenEndpointAuth}
	response := map[string]any{"client_id": clientID, "client_name": input.ClientName, "redirect_uris": input.RedirectURIs, "token_endpoint_auth_method": input.TokenEndpointAuth}
	if input.TokenEndpointAuth != "none" && input.TokenEndpointAuth != "" {
		secret := randomID()
		client.SecretHash = HashSecret(secret)
		response["client_secret"] = secret
	}
	if client.TokenEndpointAuth == "" {
		client.TokenEndpointAuth = "none"
		response["token_endpoint_auth_method"] = "none"
	}
	if err := s.Store.SaveClient(client); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.FormValue("token") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	_ = s.Store.RevokeRefreshToken(r.FormValue("token"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authenticateClient(r *http.Request) (Client, error) {
	if r.FormValue("client_assertion") != "" || r.FormValue("client_assertion_type") != "" {
		return s.authenticateClientAssertion(r)
	}
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		clientID, secret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	client, err := s.Store.GetClient(clientID)
	if err != nil {
		return Client{}, err
	}
	if client.TokenEndpointAuth == "private_key_jwt" {
		return Client{}, errors.New("client is registered for private_key_jwt and must present a client_assertion")
	}
	if client.TokenEndpointAuth == "none" || client.SecretHash == "" {
		return client, nil
	}
	if subtle.ConstantTimeCompare([]byte(client.SecretHash), []byte(HashSecret(secret))) != 1 {
		return Client{}, errors.New("invalid client secret")
	}
	return client, nil
}

// authenticateClientAssertion implements the client authentication half of
// RFC 7523 private_key_jwt: the caller proves possession of a pre-registered
// private key instead of a shared secret. This is the resource-server
// authentication that the token-exchange grant previously skipped entirely.
func (s *Server) authenticateClientAssertion(r *http.Request) (Client, error) {
	if r.FormValue("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return Client{}, errors.New("unsupported client_assertion_type")
	}
	clientID := r.FormValue("client_id")
	if clientID == "" {
		return Client{}, errors.New("client_id is required with client_assertion")
	}
	client, err := s.Store.GetClient(clientID)
	if err != nil {
		return Client{}, err
	}
	if client.TokenEndpointAuth != "private_key_jwt" || client.PublicKeyPEM == "" {
		return Client{}, errors.New("client is not registered for private_key_jwt")
	}
	tokenEndpoint := strings.TrimRight(s.Config.Issuer, "/") + "/token"
	algorithm := client.Algorithm
	if algorithm == "" {
		algorithm = "RS256"
	}
	claims, err := verifyClientAssertion(r.FormValue("client_assertion"), client.PublicKeyPEM, algorithm, clientID, tokenEndpoint)
	if err != nil {
		return Client{}, err
	}
	jti, _ := claims["jti"].(string)
	exp, _ := claims["exp"].(float64)
	if err := s.Store.ConsumeClientAssertionJTI(clientID, jti, time.Unix(int64(exp), 0)); err != nil {
		return Client{}, fmt.Errorf("client assertion rejected: %w", err)
	}
	return client, nil
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && contains(s.Config.TrustedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) httpsOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Config.RequireHTTPS && r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			oauthError(w, http.StatusBadRequest, "https_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func redirectError(w http.ResponseWriter, r *http.Request, request AuthorizationRequest, code, description, issuer string, includeIssuer bool) {
	location, _ := url.Parse(request.RedirectURI)
	query := location.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if request.State != "" {
		query.Set("state", request.State)
	}
	if includeIssuer {
		query.Set("iss", issuer)
	}
	location.RawQuery = query.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}
func validPKCE(verifier, challenge string) bool {
	digest := sha256.Sum256([]byte(verifier))
	encoded := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(challenge)) == 1
}
func validRedirect(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Fragment != "" || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html><html><body><h1>Authorize MCP client</h1><p>{{.ClientID}} requests: {{.Scopes}}</p><form method="post" action="/authorize/consent"><input type="hidden" name="consent_id" value="{{.ID}}"><button name="decision" value="approve" type="submit">Allow</button><button name="decision" value="deny" type="submit">Deny</button></form></body></html>`))
