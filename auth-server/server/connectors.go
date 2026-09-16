package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
)

// ConnectorConfig describes one provider-neutral upstream OAuth connector.
// Secrets are referenced by environment variable name and are never stored in
// this structure as literal configuration values.
type ConnectorConfig struct {
	Issuer                    string   `json:"issuer"`
	AuthorizationEndpoint     string   `json:"authorization_endpoint"`
	TokenEndpoint             string   `json:"token_endpoint"`
	JWKSURI                   string   `json:"jwks_uri"`
	ClientID                  string   `json:"client_id"`
	ClientSecretEnv           string   `json:"client_secret_env"`
	Scopes                    []string `json:"scopes"`
	MCPScopes                 []string `json:"mcp_scopes"`
	ExchangeClientID          string   `json:"exchange_client_id"`
	TokenEndpointAuthMethod   string   `json:"token_endpoint_auth_method"`
	AllowedClientRedirectURIs []string `json:"allowed_client_redirect_uris"`
}

func (c ConnectorConfig) validate(name string, allowInsecure bool) error {
	for field, value := range map[string]string{
		"issuer":                 c.Issuer,
		"authorization_endpoint": c.AuthorizationEndpoint,
		"token_endpoint":         c.TokenEndpoint,
		"jwks_uri":               c.JWKSURI,
	} {
		if value == "" {
			return fmt.Errorf("connector %q is missing %s", name, field)
		}
		parsed, err := url.Parse(value)
		validScheme := parsed.Scheme == "https" || (allowInsecure && parsed.Scheme == "http")
		if err != nil || !validScheme || parsed.Host == "" {
			return fmt.Errorf("connector %q has non-HTTPS %s", name, field)
		}
	}
	if c.ClientID == "" {
		return fmt.Errorf("connector %q is missing client_id", name)
	}
	if c.TokenEndpointAuthMethod == "" {
		return fmt.Errorf("connector %q is missing token_endpoint_auth_method", name)
	}
	if c.TokenEndpointAuthMethod != "none" && c.TokenEndpointAuthMethod != "client_secret_basic" && c.TokenEndpointAuthMethod != "client_secret_post" {
		return fmt.Errorf("connector %q has unsupported token_endpoint_auth_method", name)
	}
	if c.TokenEndpointAuthMethod != "none" && c.ClientSecretEnv == "" {
		return fmt.Errorf("connector %q requires client_secret_env", name)
	}
	if c.ExchangeClientID == "" {
		return fmt.Errorf("connector %q is missing exchange_client_id", name)
	}
	if len(c.MCPScopes) == 0 {
		return fmt.Errorf("connector %q is missing mcp_scopes", name)
	}
	for _, redirectURI := range c.AllowedClientRedirectURIs {
		parsed, err := url.Parse(redirectURI)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
			return fmt.Errorf("connector %q has invalid allowed client redirect URI", name)
		}
	}
	return nil
}

// LoadConnectors reads a JSON object keyed by connector name. A literal
// client_secret field is rejected to prevent accidental secret commits.
func LoadConnectors(path string) (map[string]ConnectorConfig, error) {
	return LoadConnectorsWithOptions(path, false)
}

// LoadConnectorsWithOptions permits HTTP endpoints only for an explicitly
// enabled local-development process. Production connector files always use
// HTTPS so upstream credentials and authorization codes are protected in transit.
func LoadConnectorsWithOptions(path string, allowInsecure bool) (map[string]ConnectorConfig, error) {
	if path == "" {
		return map[string]ConnectorConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read connectors file: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse connectors file: %w", err)
	}
	connectors := make(map[string]ConnectorConfig, len(raw))
	for name, value := range raw {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(value, &object); err != nil {
			return nil, fmt.Errorf("connector %q is not an object", name)
		}
		if _, ok := object["client_secret"]; ok {
			return nil, errors.New("connectors file must use client_secret_env, never client_secret")
		}
		var connector ConnectorConfig
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&connector); err != nil {
			return nil, fmt.Errorf("parse connector %q: %w", name, err)
		}
		if err := connector.validate(name, allowInsecure); err != nil {
			return nil, err
		}
		connectors[name] = connector
	}
	return connectors, nil
}
