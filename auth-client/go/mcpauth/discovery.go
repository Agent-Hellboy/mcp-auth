package mcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}
type AuthorizationServerMetadata struct {
	Issuer                                     string `json:"issuer"`
	AuthorizationEndpoint                      string `json:"authorization_endpoint"`
	TokenEndpoint                              string `json:"token_endpoint"`
	JWKSURI                                    string `json:"jwks_uri"`
	RegistrationEndpoint                       string `json:"registration_endpoint"`
	AuthorizationResponseIssParameterSupported bool   `json:"authorization_response_iss_parameter_supported"`
}

func DiscoverProtectedResource(client *http.Client, metadataURL string) (ProtectedResourceMetadata, error) {
	var metadata ProtectedResourceMetadata
	err := getJSON(client, metadataURL, &metadata)
	return metadata, err
}
func DiscoverAuthorizationServer(client *http.Client, issuer string) (AuthorizationServerMetadata, error) {
	return DiscoverAuthorizationServerContext(context.Background(), client, issuer)
}
func DiscoverAuthorizationServerContext(ctx context.Context, client *http.Client, issuer string) (AuthorizationServerMetadata, error) {
	var metadata AuthorizationServerMetadata
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return metadata, fmt.Errorf("invalid issuer URL")
	}
	// RFC 8414 section 3.1 first (well-known segment between host and issuer
	// path), then the OIDC-style suffix form. The suffix form is not what the
	// spec says, but it is what a path-mounted server that predates RFC 8414
	// awareness actually serves, and dropping it would strand those
	// deployments.
	for _, endpoint := range discoveryCandidates(parsed) {
		metadata = AuthorizationServerMetadata{}
		if err = getJSONContext(ctx, client, endpoint, &metadata); err == nil {
			break
		}
	}
	if err != nil {
		return AuthorizationServerMetadata{}, err
	}
	if metadata.Issuer != strings.TrimRight(issuer, "/") {
		return AuthorizationServerMetadata{}, fmt.Errorf("authorization-server metadata issuer mismatch")
	}
	return metadata, nil
}
func getJSON(client *http.Client, endpoint string, target any) error {
	return getJSONContext(context.Background(), client, endpoint, target)
}
func getJSONContext(ctx context.Context, client *http.Client, endpoint string, target any) error {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("metadata request returned %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target); err != nil {
		return err
	}
	return nil
}

// discoveryCandidates lists the metadata URLs to try, in order. An issuer with
// no path yields the same two URLs the spec and OIDC both point at, so the
// suffix entries collapse into the first two and cost nothing.
func discoveryCandidates(issuer *url.URL) []string {
	candidates := []string{
		wellKnownURL(issuer, "oauth-authorization-server"),
		wellKnownURL(issuer, "openid-configuration"),
	}
	base := strings.TrimRight(issuer.String(), "/")
	for _, name := range []string{"oauth-authorization-server", "openid-configuration"} {
		suffix := base + "/.well-known/" + name
		if suffix != candidates[0] && suffix != candidates[1] {
			candidates = append(candidates, suffix)
		}
	}
	return candidates
}

func wellKnownURL(issuer *url.URL, name string) string {
	copy := *issuer
	path := strings.Trim(copy.Path, "/")
	if path == "" {
		copy.Path = "/.well-known/" + name
	} else {
		copy.Path = "/.well-known/" + name + "/" + path
	}
	copy.RawPath = ""
	return strings.TrimRight(copy.String(), "/")
}
