package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// discoveryTimeout bounds the one-time OIDC discovery fetch at connector
// load (startup) time, so a slow or unreachable issuer fails fast instead of
// hanging server startup indefinitely.
const discoveryTimeout = 10 * time.Second

type discoveredEndpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	UserinfoEndpoint      string
}

// discoverOIDCConfiguration fetches an OIDC provider's discovery document
// (OpenID Connect Discovery 1.0, "/.well-known/openid-configuration") and
// extracts only the endpoints ConnectorConfig uses. It's used purely to fill
// in whichever of those a connector's own config leaves blank; a connector
// that already specifies everything never calls this.
func discoverOIDCConfiguration(ctx context.Context, client *http.Client, issuer string) (discoveredEndpoints, error) {
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return discoveredEndpoints{}, fmt.Errorf("create OIDC discovery request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return discoveredEndpoints{}, fmt.Errorf("fetch OIDC discovery document: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return discoveredEndpoints{}, fmt.Errorf("OIDC discovery document returned HTTP %d", response.StatusCode)
	}
	var document struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJWKSResponseBytes)).Decode(&document); err != nil {
		return discoveredEndpoints{}, fmt.Errorf("decode OIDC discovery document: %w", err)
	}
	return discoveredEndpoints{
		AuthorizationEndpoint: document.AuthorizationEndpoint,
		TokenEndpoint:         document.TokenEndpoint,
		JWKSURI:               document.JWKSURI,
		UserinfoEndpoint:      document.UserinfoEndpoint,
	}, nil
}
