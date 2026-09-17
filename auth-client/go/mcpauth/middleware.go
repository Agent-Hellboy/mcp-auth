package mcpauth

import (
	"context"
	"log"
	"net/http"
	"strings"
)

type ResourceMetadata struct {
	URL string
}

func RequireToken(verifier *JWTVerifier, metadata ResourceMetadata, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		parts := strings.Fields(header)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			writeChallenge(w, http.StatusUnauthorized, UnauthorizedHeaders(metadata.URL, nil))
			return
		}
		if verifier == nil || next == nil {
			writeChallenge(w, http.StatusInternalServerError, nil)
			return
		}
		claims, err := verifier.VerifyContext(r.Context(), parts[1])
		if err != nil {
			scopes := []string{}
			if verifier != nil {
				for scope := range verifier.RequiredScopes {
					scopes = append(scopes, scope)
				}
			}
			// Verification errors contain only a safe failure category; the
			// bearer value is never logged. This gives resource servers an
			// actionable diagnostic while preserving the generic wire response.
			log.Printf("mcp-auth token verification failed: %v", err)
			if strings.Contains(err.Error(), ": scope") {
				writeChallenge(w, http.StatusForbidden, UnauthorizedHeadersForError(metadata.URL, scopes, "insufficient_scope", "required scope is missing"))
			} else {
				writeChallenge(w, http.StatusUnauthorized, UnauthorizedHeadersForError(metadata.URL, nil, "invalid_token", "token is invalid"))
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(WithTokenClaims(r.Context(), claims)))
	})
}

type tokenClaimsContextKey struct{}

func WithTokenClaims(ctx context.Context, claims TokenClaims) context.Context {
	return context.WithValue(ctx, tokenClaimsContextKey{}, claims)
}

func TokenClaimsFromContext(ctx context.Context) (TokenClaims, bool) {
	claims, ok := ctx.Value(tokenClaimsContextKey{}).(TokenClaims)
	return claims, ok
}

func writeChallenge(w http.ResponseWriter, status int, headers map[string]string) {
	for key, value := range headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(status)
}
