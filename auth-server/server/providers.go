package server

import "context"

// IdentityProvider is the seam for a hosted login, OIDC provider, or enterprise SSO.
// The core server never imports a provider-specific SDK.
type IdentityProvider interface {
	Authenticate(context.Context, IdentityRequest) (Identity, error)
}

type IdentityRequest struct {
	ClientID string
	Nonce    string
	Resource string
	Scopes   []string
}

type Identity struct {
	Subject string
	Claims  map[string]any
}

type LocalIdentityProvider struct{ Subject string }

func (p LocalIdentityProvider) Authenticate(_ context.Context, _ IdentityRequest) (Identity, error) {
	return Identity{Subject: p.Subject}, nil
}

// TokenExchanger is optional. Implementations may call RFC 8693 or another
// provider, but must return a token whose audience matches the requested resource.
type TokenExchanger interface {
	Exchange(context.Context, ExchangeRequest) (ExchangeResponse, error)
}

type ExchangeRequest struct {
	SubjectToken       string
	RequestedTokenType string
	Audience           string
	Scope              []string
}

type ExchangeResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
}
