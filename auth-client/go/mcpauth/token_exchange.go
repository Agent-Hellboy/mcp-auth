package mcpauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type PrivateKeyJWTClientAuth struct {
	ClientID   string
	PrivateKey *rsa.PrivateKey
	KeyID      string
}

func (a PrivateKeyJWTClientAuth) Assertion(endpoint string) (string, error) {
	now := time.Now().Unix()
	header := b64JSON(map[string]any{"typ": "JWT", "alg": "RS256", "kid": a.KeyID})
	payload := b64JSON(map[string]any{"iss": a.ClientID, "sub": a.ClientID, "aud": endpoint, "iat": now, "exp": now + 300, "jti": randomString()})
	message := header + "." + payload
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type TokenExchangeClient struct {
	Endpoint   string
	HTTPClient *http.Client
	ClientAuth *PrivateKeyJWTClientAuth
	Cache      *TokenCache
}

func (c *TokenExchangeClient) Exchange(subjectToken, audience string, scopes []string) (CachedToken, error) {
	key := subjectToken + "\x00" + audience + "\x00" + strings.Join(scopes, " ")
	if c.Cache != nil {
		if token, ok := c.Cache.Get(key); ok {
			return token, nil
		}
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {subjectToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "audience": {audience}, "scope": {strings.Join(scopes, " ")}}
	if c.ClientAuth != nil {
		assertion, err := c.ClientAuth.Assertion(c.Endpoint)
		if err != nil {
			return CachedToken{}, err
		}
		form.Set("client_id", c.ClientAuth.ClientID)
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Post(c.Endpoint, "application/x-www-form-urlencoded", bytes.NewBufferString(form.Encode()))
	if err != nil {
		return CachedToken{}, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return CachedToken{}, fmt.Errorf("token exchange returned %d", response.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.AccessToken == "" {
		return CachedToken{}, fmt.Errorf("invalid token exchange response")
	}
	token := CachedToken{AccessToken: result.AccessToken, TokenType: result.TokenType, Audience: audience, ExpiresAt: time.Now().Add(time.Duration(result.ExpiresIn) * time.Second), Scopes: strings.Fields(result.Scope)}
	if c.Cache != nil {
		c.Cache.Put(key, token)
	}
	return token, nil
}
func b64JSON(value map[string]any) string {
	encoded, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(encoded)
}
func randomString() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	return base64.RawURLEncoding.EncodeToString(value[:])
}
