package mcpauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func conformanceDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate conformance test file")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "sdk-conformance")
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("sdk-conformance fixtures not found")
	return ""
}

func b64Int(t *testing.T, value string) *big.Int {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(raw)
}

func privateKeyFromJWK(t *testing.T, raw map[string]string) *rsa.PrivateKey {
	t.Helper()
	eBytes, err := base64.RawURLEncoding.DecodeString(raw["e"])
	if err != nil {
		t.Fatal(err)
	}
	e := 0
	for _, value := range eBytes {
		e = e*256 + int(value)
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: b64Int(t, raw["n"]), E: e},
		D:         b64Int(t, raw["d"]),
		Primes:    []*big.Int{b64Int(t, raw["p"]), b64Int(t, raw["q"])},
	}
	key.Precompute()
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	return key
}

func publicKeyFromJWK(t *testing.T, raw map[string]string) *rsa.PublicKey {
	t.Helper()
	eBytes, err := base64.RawURLEncoding.DecodeString(raw["e"])
	if err != nil {
		t.Fatal(err)
	}
	e := 0
	for _, value := range eBytes {
		e = e*256 + int(value)
	}
	return &rsa.PublicKey{N: b64Int(t, raw["n"]), E: e}
}

func signConformance(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	message := b64JSON(header) + "." + b64JSON(claims)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestSDKConformance(t *testing.T) {
	root := conformanceDir(t)
	var suite struct {
		MaxJWKSBytes int    `json:"max_jwks_bytes"`
		PadChar      string `json:"pad_char"`
		PadCount     int    `json:"pad_count"`
		Defaults     struct {
			Issuer    string         `json:"issuer"`
			Audience  string         `json:"audience"`
			ClockSkew int            `json:"clock_skew_seconds"`
			ExpOffset int            `json:"exp_offset_seconds"`
			Header    map[string]any `json:"header"`
			Claims    map[string]any `json:"claims"`
		} `json:"defaults"`
		Cases []struct {
			ID             string         `json:"id"`
			Kind           string         `json:"kind"`
			Expect         string         `json:"expect"`
			Header         map[string]any `json:"header"`
			Claims         map[string]any `json:"claims"`
			ExpOffset      *int           `json:"exp_offset_seconds"`
			NBFOffset      *int           `json:"nbf_offset_seconds"`
			ClockSkew      *int           `json:"clock_skew_seconds"`
			RequiredScopes []string       `json:"required_scopes"`
		} `json:"cases"`
	}
	mustReadJSON(t, filepath.Join(root, "cases.json"), &suite)
	var privateFields map[string]string
	mustReadJSON(t, filepath.Join(root, "key.json"), &privateFields)
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	mustReadJSON(t, filepath.Join(root, "jwks.json"), &jwks)
	privateKey := privateKeyFromJWK(t, privateFields)
	publicKey := publicKeyFromJWK(t, jwks.Keys[0])

	for _, testCase := range suite.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			header := map[string]any{}
			for key, value := range suite.Defaults.Header {
				header[key] = value
			}
			for key, value := range testCase.Header {
				header[key] = value
			}
			claims := map[string]any{}
			for key, value := range suite.Defaults.Claims {
				claims[key] = value
			}
			for key, value := range testCase.Claims {
				claims[key] = value
			}
			expOffset := suite.Defaults.ExpOffset
			if testCase.ExpOffset != nil {
				expOffset = *testCase.ExpOffset
			}
			claims["exp"] = time.Now().Unix() + int64(expOffset)
			if testCase.NBFOffset != nil {
				claims["nbf"] = time.Now().Unix() + int64(*testCase.NBFOffset)
			}
			token := signConformance(t, privateKey, header, claims)
			skew := suite.Defaults.ClockSkew
			if testCase.ClockSkew != nil {
				skew = *testCase.ClockSkew
			}
			required := map[string]bool{}
			for _, scope := range testCase.RequiredScopes {
				required[scope] = true
			}
			verifier := JWTVerifier{
				Issuer:         suite.Defaults.Issuer,
				Audience:       suite.Defaults.Audience,
				RequiredScopes: required,
				ClockSkew:      time.Duration(skew) * time.Second,
				JWKSCacheTTL:   time.Minute,
				keys:           map[string]*rsa.PublicKey{jwks.Keys[0]["kid"]: publicKey},
				loadedAt:       time.Now(),
			}
			if testCase.Kind == "oversized_jwks" {
				document := map[string]any{"keys": jwks.Keys, "pad": strings.Repeat(suite.PadChar, suite.PadCount)}
				body, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				if len(body) <= suite.MaxJWKSBytes {
					t.Fatalf("padded JWKS is %d bytes", len(body))
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write(body)
				}))
				defer server.Close()
				verifier.JWKSURL = server.URL
				verifier.HTTPClient = server.Client()
				verifier.keys = nil
				verifier.loadedAt = time.Time{}
			}
			_, err := verifier.Verify(token)
			if testCase.Expect == "accept" && err != nil {
				t.Fatalf("expected accept: %v", err)
			}
			if testCase.Expect == "reject" && err == nil {
				t.Fatal("expected reject")
			}
		})
	}
}

func mustReadJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
