package mcpauth

import (
	"encoding/json"
	"net/http"
	"sort"
)

// NewProtectedResourceMetadata derives the document from the verifier that
// guards the resource, so the advertised scopes cannot drift from the enforced
// ones.
func NewProtectedResourceMetadata(verifier *JWTVerifier, resource, issuer string) ProtectedResourceMetadata {
	return ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        requiredScopes(verifier),
	}
}

// ProtectedResourceMetadataHandler serves the document produced by
// NewProtectedResourceMetadata. Mount it at both
// /.well-known/oauth-protected-resource and, for a path-mounted resource, at
// /.well-known/oauth-protected-resource<resource path>.
func ProtectedResourceMetadataHandler(verifier *JWTVerifier, resource, issuer string) http.Handler {
	metadata := NewProtectedResourceMetadata(verifier, resource, issuer)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	})
}

// requiredScopes returns the verifier's required scopes in a stable order so
// the metadata document does not change between requests.
func requiredScopes(verifier *JWTVerifier) []string {
	if verifier == nil || len(verifier.RequiredScopes) == 0 {
		return nil
	}
	scopes := make([]string, 0, len(verifier.RequiredScopes))
	for scope := range verifier.RequiredScopes {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	return scopes
}
