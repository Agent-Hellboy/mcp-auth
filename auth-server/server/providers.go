package server

import (
	"context"
	"errors"
	"time"
)

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
	// UpstreamSession is the upstream provider's own token set, captured at
	// login for the "upstream_session" downstream-token strategy. nil unless
	// the identity provider that produced this Identity captured one.
	UpstreamSession *UpstreamSession
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
	// Subject is the already-verified local subject_token's "sub" claim,
	// populated by the caller (server.go's exchange handler) since it has
	// already decoded and verified that token before invoking the exchanger.
	Subject            string
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

// LocalTokenExchanger is an explicit development-only exchanger for local
// integration tests. Production deployments must provide a provider-backed
// implementation that validates the subject token and returns a downstream
// credential from the target authorization system.
type LocalTokenExchanger struct {
	Issuer      string
	KeyProvider KeyProvider
	TTL         time.Duration
}

func (e LocalTokenExchanger) Exchange(ctx context.Context, request ExchangeRequest) (ExchangeResponse, error) {
	if request.SubjectToken == "" || request.Audience == "" {
		return ExchangeResponse{}, errors.New("subject token and audience are required")
	}
	if e.KeyProvider == nil {
		return ExchangeResponse{}, errors.New("local token exchanger has no key provider")
	}
	ttl := e.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	token, err := e.KeyProvider.Sign(ctx, e.Issuer, "local-downstream-subject", request.Audience, request.Scope, ttl, "")
	if err != nil {
		return ExchangeResponse{}, err
	}
	return ExchangeResponse{AccessToken: token, TokenType: "Bearer", ExpiresIn: int(ttl.Seconds()), Scope: joinScopes(request.Scope)}, nil
}
