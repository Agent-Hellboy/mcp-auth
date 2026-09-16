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
	// Verify checks a token this provider previously signed and returns its
	// claims, so callers can confirm a bearer value actually originated here
	// before trusting it (e.g. as a token-exchange subject_token).
	Verify(context.Context, string) (map[string]any, error)
}

type LocalKeyProvider struct{ Keys *KeyManager }

func (p LocalKeyProvider) Sign(_ context.Context, issuer, subject, resource string, scopes []string, ttl time.Duration, nonce string) (string, error) {
	return p.Keys.Sign(issuer, subject, resource, scopes, ttl, nonce)
}

func (p LocalKeyProvider) JWKS(_ context.Context) (map[string]any, error) { return p.Keys.JWKS(), nil }

func (p LocalKeyProvider) Verify(_ context.Context, token string) (map[string]any, error) {
	return p.Keys.Verify(token)
}
