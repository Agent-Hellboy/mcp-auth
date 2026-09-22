package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientMetadataURLRejected(t *testing.T) {
	rejected := []string{
		"http://127.0.0.1/client.json",
		"https://user:pw@client.example.com/client.json",
		"https://client.example.com/client.json#frag",
		"https://10.1.2.3/client.json",
		"https://169.254.169.254/latest/meta-data",
	}
	for _, value := range rejected {
		if err := validateClientMetadataURL(value); err == nil {
			t.Errorf("validateClientMetadataURL(%q) accepted an unsafe URL", value)
		}
	}
	if err := validateClientMetadataURL("https://client.example.com/oauth/client.json"); err != nil {
		t.Fatalf("https hostname: %v", err)
	}
	if err := validateClientMetadataURL("https://127.0.0.1/client.json"); err != nil {
		t.Fatalf("loopback IP literal: %v", err)
	}
}

func TestClientMetadataDocumentAuthorize(t *testing.T) {
	redirectURI := "http://127.0.0.1:39999/callback"
	var clientID string
	var accept string
	metadata := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client.json" {
			http.NotFound(w, r)
			return
		}
		accept = r.Header.Get("Accept")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  clientID,
			"client_name":                "native",
			"redirect_uris":              []string{redirectURI},
			"token_endpoint_auth_method": "none",
		})
	}))
	defer metadata.Close()
	clientID = metadata.URL + "/client.json"

	instance := testServer(t)
	client := metadata.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	instance.ClientMetadataClient = client

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"resource":              {instance.Config.Resource},
	}
	request := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("CIMD authorize = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if accept != "application/json" {
		t.Fatalf("client metadata Accept = %q, want application/json", accept)
	}

	query.Set("redirect_uri", "http://127.0.0.1:39999/other")
	rejected := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	rejectedRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(rejectedRecorder, rejected)
	if rejectedRecorder.Code != http.StatusBadRequest {
		t.Fatalf("redirect outside the metadata document = %d, want 400: %s", rejectedRecorder.Code, rejectedRecorder.Body.String())
	}

	query.Set("client_id", "http://127.0.0.1/client.json")
	query.Set("redirect_uri", redirectURI)
	badScheme := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	badSchemeRecorder := httptest.NewRecorder()
	instance.Handler().ServeHTTP(badSchemeRecorder, badScheme)
	if badSchemeRecorder.Code != http.StatusBadRequest || !strings.Contains(badSchemeRecorder.Body.String(), "invalid_client") {
		t.Fatalf("http client_id = %d %s, want 400 invalid_client", badSchemeRecorder.Code, badSchemeRecorder.Body.String())
	}
}
