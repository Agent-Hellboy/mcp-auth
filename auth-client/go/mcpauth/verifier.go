package mcpauth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrInvalidToken = errors.New("invalid MCP access token")

type TokenClaims struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   map[string]bool
	Raw      map[string]any
}

type JWTVerifier struct {
	JWKSURL        string
	Issuer         string
	Audience       string
	Algorithms     map[string]bool
	RequiredScopes map[string]bool
	HTTPClient     *http.Client
	mu             sync.RWMutex
	keys           map[string]*rsa.PublicKey
	loadedAt       time.Time
	JWKSCacheTTL   time.Duration
}

func (v *JWTVerifier) Verify(token string) (TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return TokenClaims{}, ErrInvalidToken
	}
	var header map[string]any
	var claims map[string]any
	if err := decodeJSON(parts[0], &header); err != nil {
		return TokenClaims{}, ErrInvalidToken
	}
	if err := decodeJSON(parts[1], &claims); err != nil {
		return TokenClaims{}, ErrInvalidToken
	}
	algorithm, ok := header["alg"].(string)
	if !ok || !v.allowedAlgorithm(algorithm) {
		return TokenClaims{}, fmt.Errorf("%w: algorithm", ErrInvalidToken)
	}
	kid, ok := header["kid"].(string)
	if !ok {
		return TokenClaims{}, fmt.Errorf("%w: kid", ErrInvalidToken)
	}
	if err := v.ensureKeys(kid); err != nil {
		return TokenClaims{}, err
	}
	v.mu.RLock()
	key := v.keys[kid]
	v.mu.RUnlock()
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return TokenClaims{}, fmt.Errorf("%w: signature", ErrInvalidToken)
	}
	if claims["iss"] != v.Issuer || !validTime(claims["exp"]) || !audienceContains(claims["aud"], v.Audience) {
		return TokenClaims{}, ErrInvalidToken
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return TokenClaims{}, ErrInvalidToken
	}
	scopes := map[string]bool{}
	if scope, ok := claims["scope"].(string); ok {
		for _, value := range strings.Fields(scope) {
			scopes[value] = true
		}
	}
	for required := range v.RequiredScopes {
		if !scopes[required] {
			return TokenClaims{}, fmt.Errorf("%w: scope", ErrInvalidToken)
		}
	}
	return TokenClaims{Subject: subject, Issuer: v.Issuer, Audience: audienceValues(claims["aud"]), Scopes: scopes, Raw: claims}, nil
}

func (v *JWTVerifier) allowedAlgorithm(value string) bool {
	if len(v.Algorithms) == 0 {
		return value == "RS256"
	}
	return v.Algorithms[value]
}
func validTime(value any) bool {
	number, ok := value.(float64)
	return ok && time.Now().Before(time.Unix(int64(number), 0))
}
func audienceContains(value any, expected string) bool {
	for _, item := range audienceValues(value) {
		if item == expected {
			return true
		}
	}
	return false
}
func audienceValues(value any) []string {
	switch item := value.(type) {
	case string:
		return []string{item}
	case []any:
		values := []string{}
		for _, candidate := range item {
			if text, ok := candidate.(string); ok {
				values = append(values, text)
			}
		}
		return values
	}
	return nil
}
func decodeJSON(value string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(decoded, target)
}

func (v *JWTVerifier) ensureKeys(kid string) error {
	if v.JWKSCacheTTL <= 0 {
		v.JWKSCacheTTL = 5 * time.Minute
	}
	v.mu.RLock()
	fresh := len(v.keys) > 0 && time.Since(v.loadedAt) < v.JWKSCacheTTL
	_, found := v.keys[kid]
	v.mu.RUnlock()
	if fresh && found {
		return nil
	}
	if v.JWKSURL == "" {
		return fmt.Errorf("%w: JWKS unavailable", ErrInvalidToken)
	}
	client := v.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Get(v.JWKSURL)
	if err != nil {
		return fmt.Errorf("%w: JWKS request", ErrInvalidToken)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: JWKS status", ErrInvalidToken)
	}
	var raw struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&raw); err != nil {
		return fmt.Errorf("%w: JWKS JSON", ErrInvalidToken)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range raw.Keys {
		if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" {
			continue
		}
		modulus, errN := base64.RawURLEncoding.DecodeString(jwk["n"])
		exponent, errE := base64.RawURLEncoding.DecodeString(jwk["e"])
		if errN != nil || errE != nil || len(exponent) == 0 {
			continue
		}
		e := 0
		for _, value := range exponent {
			e = e*256 + int(value)
		}
		keys[jwk["kid"]] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}
	}
	v.mu.Lock()
	v.keys, v.loadedAt = keys, time.Now()
	v.mu.Unlock()
	v.mu.RLock()
	_, found = v.keys[kid]
	v.mu.RUnlock()
	if !found {
		return fmt.Errorf("%w: key not found", ErrInvalidToken)
	}
	return nil
}
