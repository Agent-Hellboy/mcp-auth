package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

type KeyManager struct {
	PrivateKey *rsa.PrivateKey
	KeyID      string
}

func NewKeyManager(path string) (*KeyManager, error) {
	if path == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate local signing key: %w", err)
		}
		return &KeyManager{PrivateKey: key, KeyID: "local-generated"}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("signing key is not PEM encoded")
	}
	var key *rsa.PrivateKey
	if parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	} else if parsed, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		key = parsed
	}
	if key == nil {
		return nil, errors.New("signing key is not an RSA private key")
	}
	return &KeyManager{PrivateKey: key, KeyID: "configured-rsa"}, nil
}

func (k *KeyManager) JWKS() map[string]any {
	public := k.PrivateKey.PublicKey
	return map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.KeyID,
		"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}}
}

func (k *KeyManager) Sign(issuer, subject, resource string, scopes []string, ttl time.Duration, nonce string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{"iss": issuer, "sub": subject, "aud": resource, "iat": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": randomID(), "scope": joinScopes(scopes)}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": k.KeyID}
	headEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(header))
	claimEncoded := base64.RawURLEncoding.EncodeToString(mustJSON(claims))
	message := []byte(headEncoded + "." + claimEncoded)
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, k.PrivateKey, cryptoHashSHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return string(message) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Kept as a named value to make the signing primitive explicit in audits.
var cryptoHashSHA256 = cryptoHash()

func cryptoHash() crypto.Hash { return crypto.SHA256 }

func randomID() string {
	var value [24]byte
	_, _ = rand.Read(value[:])
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func joinScopes(scopes []string) string { return strings.Join(scopes, " ") }
