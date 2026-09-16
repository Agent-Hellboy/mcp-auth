package mcpauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}
type AuthorizationServerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

func DiscoverProtectedResource(client *http.Client, metadataURL string) (ProtectedResourceMetadata, error) {
	var metadata ProtectedResourceMetadata
	err := getJSON(client, metadataURL, &metadata)
	return metadata, err
}
func DiscoverAuthorizationServer(client *http.Client, issuer string) (AuthorizationServerMetadata, error) {
	var metadata AuthorizationServerMetadata
	err := getJSON(client, strings.TrimRight(issuer, "/")+"/.well-known/oauth-authorization-server", &metadata)
	return metadata, err
}
func getJSON(client *http.Client, endpoint string, target any) error {
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return fmt.Errorf("metadata request returned %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		return err
	}
	return nil
}
