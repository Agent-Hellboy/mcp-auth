package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/example/mcp-auth/auth-server/server"
)

func main() {
	config := server.ConfigFromEnv()
	if err := config.Validate(); err != nil {
		slog.Error("invalid server configuration", "error", err)
		os.Exit(1)
	}
	store, closeStore, err := buildStore(config)
	if err != nil {
		slog.Error("store initialization failed", "error", err)
		os.Exit(1)
	}
	defer closeStore()

	config, identityProvider, tokenExchanger, err := buildProviders(config)
	if err != nil {
		slog.Error("provider initialization failed", "error", err)
		os.Exit(1)
	}
	authServer, err := server.NewServer(config, store, identityProvider, tokenExchanger, os.Stderr)
	if err != nil {
		slog.Error("server initialization failed", "error", err)
		os.Exit(1)
	}
	if err := loadResourceClients(authServer.Store, config.ResourceClientsFile); err != nil {
		slog.Error("resource client registration failed", "error", err)
		os.Exit(1)
	}
	if config.LocalDevelopment && config.LocalClientID != "" {
		if err := authServer.Store.SaveClient(server.Client{
			ID:                config.LocalClientID,
			Name:              "local resource server",
			RedirectURIs:      []string{"http://127.0.0.1:39001/callback"},
			TokenEndpointAuth: "none",
		}); err != nil {
			slog.Error("local client registration failed", "error", err)
			os.Exit(1)
		}
	}
	if config.LocalDevelopment && config.LocalTokenExchange {
		authServer.TokenExchanger = server.LocalTokenExchanger{
			Issuer:      config.Issuer,
			KeyProvider: authServer.KeyProvider,
			TTL:         config.AccessTokenTTL,
		}
	}
	if config.LocalDevelopment && config.PrivateKeyFile == "" {
		slog.Warn("INSECURE LOCAL DEVELOPMENT: using an ephemeral signing key; all tokens become invalid after restart")
	}
	slog.Info("mcp auth server listening", "addr", config.ListenAddr, "issuer", config.Issuer)
	if err := http.ListenAndServe(config.ListenAddr, authServer.Handler()); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// loadResourceClients registers pre-provisioned private_key_jwt clients (for
// example, a resource server performing RFC 8693 token exchange) so the
// token endpoint can authenticate them. Registration is re-applied on every
// startup, so the file is the source of truth and edits take effect on restart.
func loadResourceClients(store server.Store, path string) error {
	if path == "" {
		return nil
	}
	clients, err := server.LoadResourceClients(path)
	if err != nil {
		return err
	}
	for _, client := range clients {
		if err := store.SaveClient(server.Client{
			ID:                client.ClientID,
			Name:              client.Name,
			TokenEndpointAuth: "private_key_jwt",
			PublicKeyPEM:      client.PublicKeyPEM,
		}); err != nil {
			return fmt.Errorf("register resource client %q: %w", client.ClientID, err)
		}
	}
	return nil
}

func buildStore(config server.Config) (server.Store, func(), error) {
	switch strings.ToLower(config.StoreBackend) {
	case "memory":
		return server.NewMemoryStore(), func() {}, nil
	case "sqlite":
		store, err := server.NewSQLiteStore(config.DatabaseURL)
		if err != nil {
			return nil, nil, err
		}
		return store, func() { _ = store.Close() }, nil
	default:
		return nil, nil, errors.New("unsupported store backend")
	}
}

func buildProviders(config server.Config) (server.Config, server.IdentityProvider, server.TokenExchanger, error) {
	if config.ConnectorName == "" {
		if !config.LocalDevelopment {
			return config, nil, nil, errors.New("a named connector is required outside local development")
		}
		return config, server.LocalIdentityProvider{Subject: config.LocalSubject}, nil, nil
	}
	allowInsecure := config.LocalDevelopment || config.AllowInsecureConnectors
	connectors, err := server.LoadConnectorsWithOptions(config.ConnectorsFile, allowInsecure)
	if err != nil {
		return config, nil, nil, err
	}
	connector, ok := connectors[config.ConnectorName]
	if !ok {
		return config, nil, nil, errors.New("configured connector was not found")
	}
	config.AllowedScopes = append([]string(nil), connector.MCPScopes...)
	config.AllowedClientRedirectURIs = append([]string(nil), connector.AllowedClientRedirectURIs...)
	callbackURL := strings.TrimRight(config.Issuer, "/") + "/identity/callback"
	identity, err := server.NewOIDCIdentityProvider(connector, callbackURL, allowInsecure)
	if err != nil {
		return config, nil, nil, err
	}
	exchanger, err := server.NewOIDCTokenExchanger(connector, allowInsecure)
	if err != nil {
		return config, nil, nil, err
	}
	return config, identity, exchanger, nil
}
