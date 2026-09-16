package server

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Issuer                      string
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
	AuthorizationResponseIssuer bool
	LocalTokenExchange          bool
	RequireHTTPS                bool
}

func ConfigFromEnv() Config {
	return Config{
		Issuer:                      env("MCP_AUTH_ISSUER", "http://localhost:8080"),
		Resource:                    env("MCP_AUTH_RESOURCE", "http://localhost:8081/mcp"),
		ListenAddr:                  env("MCP_AUTH_LISTEN_ADDR", ":8080"),
		AccessTokenTTL:              durationEnv("MCP_AUTH_ACCESS_TOKEN_TTL", 10*time.Minute),
		RefreshTokenTTL:             durationEnv("MCP_AUTH_REFRESH_TOKEN_TTL", 24*time.Hour),
		AuthorizationCodeTTL:        durationEnv("MCP_AUTH_AUTHORIZATION_CODE_TTL", 2*time.Minute),
		AllowedScopes:               csvEnv("MCP_AUTH_ALLOWED_SCOPES", []string{"tools:read", "tools:write"}),
		TrustedOrigins:              csvEnv("MCP_AUTH_TRUSTED_ORIGINS", nil),
		PrivateKeyFile:              os.Getenv("MCP_AUTH_PRIVATE_KEY_FILE"),
		RegistrationEnabled:         boolEnv("MCP_AUTH_REGISTRATION_ENABLED", true),
		LocalDevelopment:            boolEnv("MCP_AUTH_LOCAL_DEVELOPMENT", true),
		LocalSubject:                env("MCP_AUTH_LOCAL_SUBJECT", "local-user"),
		AuthorizationResponseIssuer: boolEnv("MCP_AUTH_AUTHORIZATION_RESPONSE_ISS", true),
		LocalTokenExchange:          boolEnv("MCP_AUTH_LOCAL_TOKEN_EXCHANGE", false),
		RequireHTTPS:                boolEnv("MCP_AUTH_REQUIRE_HTTPS", false),
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
