package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// InteractiveIdentityProvider adds the browser redirect/callback seam needed
// by an upstream OAuth/OIDC provider while preserving the small core interface.
type InteractiveIdentityProvider interface {
	IdentityProvider
	Begin(context.Context, IdentityRequest, string) (string, error)
	Complete(context.Context, IdentityCallback) (Identity, error)
}

type IdentityCallback struct {
	Code        string
	RedirectURI string
	Nonce       string
	State       string
}

// OIDCIdentityProvider performs an upstream Authorization Code + PKCE flow and
// verifies the returned RS256 ID token before exposing subject/claims locally.
type OIDCIdentityProvider struct {
	Connector   ConnectorConfig
	Client      *http.Client
	CallbackURL string
	Secret      string
	pending     sync.Map // upstream state -> PKCE verifier
}

func NewOIDCIdentityProvider(connector ConnectorConfig, callbackURL string) (*OIDCIdentityProvider, error) {
	if err := connector.validate("selected", true); err != nil {
		return nil, err
	}
	if len(connector.AllowedClientRedirectURIs) > 0 && !contains(connector.AllowedClientRedirectURIs, callbackURL) {
		return nil, errors.New("OIDC callback URL is not in allowed_client_redirect_uris")
	}
	secret, err := connectorSecret(connector)
	if err != nil {
		return nil, err
	}
	return &OIDCIdentityProvider{Connector: connector, Client: http.DefaultClient, CallbackURL: callbackURL, Secret: secret}, nil
}

func (p *OIDCIdentityProvider) Authenticate(context.Context, IdentityRequest) (Identity, error) {
	return Identity{}, errors.New("OIDC identity provider requires interactive browser authentication")
}

func (p *OIDCIdentityProvider) Begin(_ context.Context, request IdentityRequest, state string) (string, error) {
	if state == "" || request.Nonce == "" {
		return "", errors.New("OIDC state and nonce are required")
	}
	codeVerifier := randomID() + randomID()
	p.pending.Store(state, codeVerifier)
	digest := sha256.Sum256([]byte(codeVerifier))
	scopes := append([]string(nil), p.Connector.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.Connector.ClientID},
		"redirect_uri":          {p.CallbackURL},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {request.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	return p.Connector.AuthorizationEndpoint + "?" + values.Encode(), nil
}

func (p *OIDCIdentityProvider) Complete(ctx context.Context, callback IdentityCallback) (Identity, error) {
	if callback.Code == "" || callback.RedirectURI == "" || callback.State == "" {
		return Identity{}, errors.New("OIDC callback code and redirect URI are required")
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {callback.Code},
		"redirect_uri": {callback.RedirectURI},
		"client_id":    {p.Connector.ClientID},
	}
	if verifier, ok := p.pending.LoadAndDelete(callback.State); ok {
		form.Set("code_verifier", verifier.(string))
	} else {
		return Identity{}, errors.New("OIDC upstream state is invalid or expired")
	}
	if p.Client == nil {
		p.Client = http.DefaultClient
	}
	if p.Connector.TokenEndpointAuthMethod == "client_secret_post" {
		form.Set("client_secret", p.Secret)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Connector.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, fmt.Errorf("create OIDC token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.Connector.TokenEndpointAuthMethod == "client_secret_basic" {
		request.SetBasicAuth(p.Connector.ClientID, p.Secret)
	}
	response, err := p.Client.Do(request)
	if err != nil {
		return Identity{}, fmt.Errorf("OIDC token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Identity{}, fmt.Errorf("OIDC token request returned HTTP %d", response.StatusCode)
	}
	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return Identity{}, fmt.Errorf("decode OIDC token response: %w", err)
	}
	if tokenResponse.IDToken == "" {
		return Identity{}, errors.New("OIDC token response has no id_token")
	}
	claims, err := verifyOIDCIDToken(ctx, p.Client, p.Connector, tokenResponse.IDToken, callback.Nonce)
	if err != nil {
		return Identity{}, err
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return Identity{}, errors.New("OIDC ID token has no subject")
	}
	return Identity{Subject: subject, Claims: claims}, nil
}

// OIDCTokenExchanger implements RFC 8693 against the selected provider.
type OIDCTokenExchanger struct {
	Connector ConnectorConfig
	Client    *http.Client
	Secret    string
}

func NewOIDCTokenExchanger(connector ConnectorConfig) (*OIDCTokenExchanger, error) {
	if err := connector.validate("selected", true); err != nil {
		return nil, err
	}
	secret, err := connectorSecret(connector)
	if err != nil {
		return nil, err
	}
	return &OIDCTokenExchanger{Connector: connector, Client: http.DefaultClient, Secret: secret}, nil
}

func (e *OIDCTokenExchanger) Exchange(ctx context.Context, exchange ExchangeRequest) (ExchangeResponse, error) {
	if exchange.SubjectToken == "" || exchange.Audience == "" {
		return ExchangeResponse{}, errors.New("subject token and audience are required")
	}
	if e.Client == nil {
		e.Client = http.DefaultClient
	}
	clientID := e.Connector.ExchangeClientID
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {exchange.SubjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {requestedTokenType(exchange.RequestedTokenType)},
		"audience":             {exchange.Audience},
		"scope":                {strings.Join(exchange.Scope, " ")},
		"client_id":            {clientID},
	}
	if e.Connector.TokenEndpointAuthMethod == "client_secret_post" {
		form.Set("client_secret", e.Secret)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Connector.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("create token exchange request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if e.Connector.TokenEndpointAuthMethod == "client_secret_basic" {
		request.SetBasicAuth(clientID, e.Secret)
	}
	response, err := e.Client.Do(request)
	if err != nil {
		return ExchangeResponse{}, fmt.Errorf("token exchange request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ExchangeResponse{}, fmt.Errorf("token exchange returned HTTP %d", response.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return ExchangeResponse{}, fmt.Errorf("decode token exchange response: %w", err)
	}
	if token.AccessToken == "" {
		return ExchangeResponse{}, errors.New("token exchange response has no access_token")
	}
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}
	return ExchangeResponse{AccessToken: token.AccessToken, TokenType: token.TokenType, ExpiresIn: token.ExpiresIn, Scope: token.Scope}, nil
}

func requestedTokenType(value string) string {
	if value == "" {
		return "urn:ietf:params:oauth:token-type:access_token"
	}
	return value
}

func connectorSecret(connector ConnectorConfig) (string, error) {
	if connector.TokenEndpointAuthMethod == "none" {
		return "", nil
	}
	secret := strings.TrimSpace(os.Getenv(connector.ClientSecretEnv))
	if secret == "" {
		return "", fmt.Errorf("client secret environment variable %q is empty", connector.ClientSecretEnv)
	}
	return secret, nil
}

func verifyOIDCIDToken(ctx context.Context, client *http.Client, connector ConnectorConfig, token, expectedNonce string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("OIDC ID token is malformed")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return nil, errors.New("OIDC ID token algorithm or key is invalid")
	}
	var claims map[string]any
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return nil, errors.New("OIDC ID token claims are invalid")
	}
	key, err := fetchRSAKey(ctx, client, connector.JWKSURI, header.KeyID)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return nil, errors.New("OIDC ID token signature is invalid")
	}
	if claims["iss"] != connector.Issuer {
		return nil, errors.New("OIDC ID token issuer is invalid")
	}
	if !audienceContains(claims["aud"], connector.ClientID) {
		return nil, errors.New("OIDC ID token audience is invalid")
	}
	if !validExpiry(claims["exp"]) {
		return nil, errors.New("OIDC ID token is expired")
	}
	if expectedNonce != "" && claims["nonce"] != expectedNonce {
		return nil, errors.New("OIDC ID token nonce is invalid")
	}
	return claims, nil
}

func decodeJWTPart(encoded string, destination any) error {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, destination)
}

func audienceContains(value any, expected string) bool {
	switch audience := value.(type) {
	case string:
		return audience == expected
	case []any:
		for _, item := range audience {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func validExpiry(value any) bool {
	seconds, ok := value.(float64)
	return ok && time.Now().Unix() < int64(seconds)
}

func fetchRSAKey(ctx context.Context, client *http.Client, endpoint, keyID string) (*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch OIDC JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("OIDC JWKS returned HTTP %d", response.StatusCode)
	}
	var document struct {
		Keys []struct {
			KeyType string `json:"kty"`
			KeyID   string `json:"kid"`
			N       string `json:"n"`
			E       string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return nil, fmt.Errorf("decode OIDC JWKS: %w", err)
	}
	for _, candidate := range document.Keys {
		if candidate.KeyType != "RSA" || candidate.KeyID != keyID {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(candidate.N)
		e, errE := base64.RawURLEncoding.DecodeString(candidate.E)
		if errN != nil || errE != nil {
			return nil, errors.New("OIDC JWKS RSA key is malformed")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, errors.New("OIDC JWKS signing key was not found")
}
