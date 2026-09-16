package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"time"
)

type AuditLogger struct{ logger *slog.Logger }

func NewAuditLogger(w io.Writer) *AuditLogger {
	return &AuditLogger{logger: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{}))}
}

func (a *AuditLogger) Event(name, outcome string, attrs map[string]any) {
	clean := map[string]any{"event": name, "outcome": outcome, "time": time.Now().UTC().Format(time.RFC3339Nano)}
	for key, value := range attrs {
		if isSensitive(key) {
			continue
		}
		clean[key] = value
	}
	a.logger.Info("oauth event", "data", json.RawMessage(mustJSON(clean)))
}

func isSensitive(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "key") || strings.Contains(key, "code") || strings.Contains(key, "assertion")
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
