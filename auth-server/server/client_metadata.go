package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// clientMetadataTimeout bounds an OAuth Client ID Metadata Document fetch.
// The URL is caller-supplied, so a slow host must not stall /authorize.
const clientMetadataTimeout = 5 * time.Second

// clientMetadataError is a rejected Client ID Metadata Document. Error is the
// OAuth error code; detail is safe to put in error_description and the audit log.
type clientMetadataError struct{ detail string }

func (e *clientMetadataError) Error() string { return "invalid_client" }

// errUnknownClient is returned when /authorize names a client_id that is not
// registered and is not a Client ID Metadata Document URL.
var errUnknownClient = errors.New("unknown client")

func isClientIDURL(clientID string) bool {
	parsed, err := url.Parse(clientID)
	if err != nil || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || parsed.Scheme == "http"
}

// validateClientMetadataURL applies the SSRF limits on a client_id URL:
// HTTPS only, no credentials, no fragment, and no non-loopback IP literal.
// A hostname is not resolved, so a name that points at a private address is
// not rejected here.
func validateClientMetadataURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
		return errors.New("client_id metadata URL must be https without credentials or a fragment")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && !ip.IsLoopback() {
		return errors.New("client_id metadata URL must not use a non-loopback IP address")
	}
	return nil
}

func (s *Server) metadataHTTPClient() *http.Client {
	if s.ClientMetadataClient != nil {
		return s.ClientMetadataClient
	}
	return defaultClientMetadataClient
}

var defaultClientMetadataClient = &http.Client{
	Timeout: clientMetadataTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchClientMetadata loads an OAuth Client ID Metadata Document
// (draft-ietf-oauth-client-id-metadata-document-00). Dynamic client
// registration stays available for clients that are not identified by a URL.
// Only token_endpoint_auth_method "none" is accepted: a metadata document
// does not establish a client secret with this server.
func (s *Server) fetchClientMetadata(ctx context.Context, clientID string) (Client, error) {
	if err := validateClientMetadataURL(clientID); err != nil {
		return Client{}, &clientMetadataError{detail: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, clientMetadataTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return Client{}, &clientMetadataError{detail: "client metadata URL is not fetchable"}
	}
	request.Header.Set("Accept", "application/json")
	response, err := s.metadataHTTPClient().Do(request)
	if err != nil {
		return Client{}, &clientMetadataError{detail: "client metadata document could not be fetched"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Client{}, &clientMetadataError{detail: fmt.Sprintf("client metadata document returned HTTP %d", response.StatusCode)}
	}
	var document struct {
		ClientID          string   `json:"client_id"`
		ClientName        string   `json:"client_name"`
		RedirectURIs      []string `json:"redirect_uris"`
		TokenEndpointAuth string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxJWKSResponseBytes)).Decode(&document); err != nil {
		return Client{}, &clientMetadataError{detail: "client metadata document is not valid JSON"}
	}
	if document.ClientID != clientID {
		return Client{}, &clientMetadataError{detail: "client metadata client_id does not match the requested URL"}
	}
	if len(document.RedirectURIs) == 0 {
		return Client{}, &clientMetadataError{detail: "client metadata document has no redirect_uris"}
	}
	for _, redirectURI := range document.RedirectURIs {
		if !validRedirect(redirectURI) {
			return Client{}, &clientMetadataError{detail: "client metadata document has an invalid redirect_uri"}
		}
	}
	authMethod := document.TokenEndpointAuth
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		return Client{}, &clientMetadataError{detail: "client metadata documents must use token_endpoint_auth_method none"}
	}
	return Client{
		ID:                clientID,
		Name:              document.ClientName,
		RedirectURIs:      document.RedirectURIs,
		TokenEndpointAuth: authMethod,
	}, nil
}

func (s *Server) resolveClient(ctx context.Context, clientID string) (Client, error) {
	if strings.TrimSpace(clientID) == "" {
		return Client{}, errUnknownClient
	}
	if isClientIDURL(clientID) {
		return s.fetchClientMetadata(ctx, clientID)
	}
	client, err := s.Store.GetClient(clientID)
	if err != nil {
		return Client{}, errUnknownClient
	}
	return client, nil
}
