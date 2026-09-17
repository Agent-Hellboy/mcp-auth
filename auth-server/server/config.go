package server

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Issuer    string
	Resources []string
	// Resource is retained for source compatibility; use Resources for new code.
	Resource                    string
	ListenAddr                  string
	AccessTokenTTL              time.Duration
	RefreshTokenTTL             time.Duration
	AuthorizationCodeTTL        time.Duration
	AllowedScopes               []string
	TrustedOrigins              []string
	PrivateKeyFile              string
	RegistrationEnabled         bool
	LocalDevelopment            bool
	LocalSubject                string
	LocalClientID               string
	AuthorizationResponseIssuer bool
	LocalTokenExchange          bool
	RequireHTTPS                bool
	AllowInsecureConnectors     bool
	ConnectorsFile              string
	ConnectorName               string
	StoreBackend                string
	DatabaseURL                 string
}

// Validate applies deployment safety checks that are intentionally separate
// from NewServer so tests and embedders can supply their own transport setup.
func (c Config) Validate() error {
	resources := c.configuredResources()
	if c.Issuer == "" || len(resources) == 0 {
		return errors.New("issuer and resource are required")
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Hostname() == "" || issuer.Scheme == "" {
		return errors.New("issuer must be an absolute URL")
	}
	for _, value := range resources {
		resource, err := url.Parse(value)
		if err != nil || resource.Hostname() == "" || resource.Scheme == "" {
			return errors.New("resources must be absolute URLs")
		}
	}
	if c.RequireHTTPS && issuer.Scheme != "https" {
		return errors.New("issuer and resource must use HTTPS when MCP_AUTH_REQUIRE_HTTPS is enabled")
	}
	if c.RequireHTTPS {
		for _, value := range resources {
			if parsed, _ := url.Parse(value); parsed.Scheme != "https" {
				return errors.New("issuer and resource must use HTTPS when MCP_AUTH_REQUIRE_HTTPS is enabled")
			}
		}
	}
	if c.AllowInsecureConnectors && c.RequireHTTPS {
		return errors.New("insecure connector transport requires MCP_AUTH_REQUIRE_HTTPS=false")
	}
	if c.LocalDevelopment && !isLoopbackHost(issuer.Hostname()) {
		return fmt.Errorf("local development is only allowed with a loopback issuer, got %q", issuer.Hostname())
	}
	if !c.LocalDevelopment && c.PrivateKeyFile == "" {
		return errors.New("MCP_AUTH_PRIVATE_KEY_FILE is required outside local development")
	}
	storeBackend := strings.ToLower(c.StoreBackend)
	if !c.LocalDevelopment && storeBackend == "memory" {
		return errors.New("memory store is only allowed in local development")
	}
	if storeBackend != "memory" && storeBackend != "sqlite" {
		return fmt.Errorf("unsupported store backend %q", c.StoreBackend)
	}
	if storeBackend == "sqlite" && c.DatabaseURL == "" {
		return errors.New("MCP_AUTH_DATABASE_URL is required for the sqlite store")
	}
	if c.ConnectorName != "" && c.ConnectorsFile == "" {
		return errors.New("MCP_AUTH_CONNECTORS_FILE is required when MCP_AUTH_CONNECTOR is set")
	}
	if c.ConnectorsFile != "" && c.ConnectorName == "" {
		return errors.New("MCP_AUTH_CONNECTOR is required when MCP_AUTH_CONNECTORS_FILE is set")
	}
	return nil
}

func (c Config) configuredResources() []string {
	if len(c.Resources) > 0 {
		return append([]string(nil), c.Resources...)
	}
	if c.Resource != "" {
		return []string{c.Resource}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func ConfigFromEnv() Config {
	return Config{
		Issuer:                      env("MCP_AUTH_ISSUER", "http://localhost:8080"),
		Resources:                   csvEnv("MCP_AUTH_RESOURCES", nil),
		Resource:                    env("MCP_AUTH_RESOURCE", "http://localhost:8081/mcp"),
		ListenAddr:                  env("MCP_AUTH_LISTEN_ADDR", ":8080"),
		AccessTokenTTL:              durationEnv("MCP_AUTH_ACCESS_TOKEN_TTL", 10*time.Minute),
		RefreshTokenTTL:             durationEnv("MCP_AUTH_REFRESH_TOKEN_TTL", 24*time.Hour),
		AuthorizationCodeTTL:        durationEnv("MCP_AUTH_AUTHORIZATION_CODE_TTL", 2*time.Minute),
		AllowedScopes:               csvEnv("MCP_AUTH_ALLOWED_SCOPES", []string{"tools:read", "tools:write"}),
		TrustedOrigins:              csvEnv("MCP_AUTH_TRUSTED_ORIGINS", nil),
		PrivateKeyFile:              os.Getenv("MCP_AUTH_PRIVATE_KEY_FILE"),
		RegistrationEnabled:         boolEnv("MCP_AUTH_REGISTRATION_ENABLED", false),
		LocalDevelopment:            boolEnv("MCP_AUTH_LOCAL_DEVELOPMENT", false),
		LocalSubject:                env("MCP_AUTH_LOCAL_SUBJECT", "local-user"),
		LocalClientID:               os.Getenv("MCP_AUTH_LOCAL_CLIENT_ID"),
		AuthorizationResponseIssuer: boolEnv("MCP_AUTH_AUTHORIZATION_RESPONSE_ISS", true),
		LocalTokenExchange:          boolEnv("MCP_AUTH_LOCAL_TOKEN_EXCHANGE", false),
		RequireHTTPS:                boolEnv("MCP_AUTH_REQUIRE_HTTPS", true),
		AllowInsecureConnectors:     boolEnv("MCP_AUTH_ALLOW_INSECURE_CONNECTORS", false),
		ConnectorsFile:              os.Getenv("MCP_AUTH_CONNECTORS_FILE"),
		ConnectorName:               os.Getenv("MCP_AUTH_CONNECTOR"),
		StoreBackend:                env("MCP_AUTH_STORE", "memory"),
		DatabaseURL:                 os.Getenv("MCP_AUTH_DATABASE_URL"),
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func boolEnv(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func csvEnv(name string, fallback []string) []string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
