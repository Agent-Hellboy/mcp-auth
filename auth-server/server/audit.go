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

// Request logs one line per inbound HTTP request: enough to answer "did the
// request even arrive, and what did we send back" without opening the
// store. clientID is omitted when empty (most requests, including every
// GET, have none to report) rather than logged as "".
func (a *AuditLogger) Request(requestID, method, path string, status int, duration time.Duration, clientID string) {
	attrs := map[string]any{
		"event": "http_request", "request_id": requestID, "method": method,
		"path": path, "status": status, "duration_ms": duration.Milliseconds(),
	}
	if clientID != "" {
		attrs["client_id"] = clientID
	}
	a.logger.Info("http request", "data", json.RawMessage(mustJSON(attrs)))
}

func isSensitive(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "key") || strings.Contains(key, "code") || strings.Contains(key, "assertion")
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
