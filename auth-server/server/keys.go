package server

import (
	"context"
	"time"
)

// KeyProvider is the production boundary for signing and public-key publication.
// A KMS/HSM or secret-manager adapter can implement it without changing handlers.
type KeyProvider interface {
	Sign(context.Context, string, string, string, []string, time.Duration, string) (string, error)
	JWKS(context.Context) (map[string]any, error)
}

type LocalKeyProvider struct{ Keys *KeyManager }

func (p LocalKeyProvider) Sign(_ context.Context, issuer, subject, resource string, scopes []string, ttl time.Duration, nonce string) (string, error) {
	return p.Keys.Sign(issuer, subject, resource, scopes, ttl, nonce)
}

func (p LocalKeyProvider) JWKS(_ context.Context) (map[string]any, error) { return p.Keys.JWKS(), nil }
