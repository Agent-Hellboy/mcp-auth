package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/example/mcp-auth/auth-server/server"
)

func main() {
	config := server.ConfigFromEnv()
	authServer, err := server.NewServer(config, server.NewMemoryStore(), server.LocalIdentityProvider{Subject: config.LocalSubject}, nil, os.Stderr)
	if err != nil {
		slog.Error("server initialization failed", "error", err)
		os.Exit(1)
	}
	if config.LocalDevelopment && config.LocalTokenExchange {
		authServer.TokenExchanger = server.LocalTokenExchanger{
			Issuer:      config.Issuer,
			KeyProvider: authServer.KeyProvider,
			TTL:         config.AccessTokenTTL,
		}
	}
	slog.Info("mcp auth server listening", "addr", config.ListenAddr, "issuer", config.Issuer)
	if err := http.ListenAndServe(config.ListenAddr, authServer.Handler()); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
