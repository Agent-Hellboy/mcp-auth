package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("record not found")
var ErrAlreadyUsed = errors.New("record already used")

type Client struct {
	ID                string
	Name              string
	RedirectURIs      []string
	TokenEndpointAuth string
	SecretHash        string
	// PublicKeyPEM holds an RSA public key (PKIX, PEM-encoded) for clients
	// registered with TokenEndpointAuth "private_key_jwt". It is never secret.
	PublicKeyPEM string
}

type AuthorizationCode struct {
	ValueHash     string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Scope         []string
	Resource      string
	Subject       string
	Nonce         string
	ExpiresAt     time.Time
	Used          bool
}

type RefreshToken struct {
	ValueHash string
	ClientID  string
	Subject   string
	Scope     []string
	Resource  string
	ExpiresAt time.Time
	Used      bool
	Revoked   bool
}

type ConsentRequest struct {
	ValueHash string
	Request   AuthorizationRequest
	Nonce     string
	ExpiresAt time.Time
}

type Store interface {
	SaveClient(Client) error
	GetClient(string) (Client, error)
	SaveAuthorizationCode(AuthorizationCode) error
	ConsumeAuthorizationCode(string, time.Time) (AuthorizationCode, error)
	SaveRefreshToken(RefreshToken) error
	ConsumeRefreshToken(string, time.Time) (RefreshToken, error)
	RevokeRefreshToken(string) error
	SaveConsentRequest(ConsentRequest) error
	ConsumeConsentRequest(string, time.Time) (ConsentRequest, error)
	// ConsumeClientAssertionJTI records a client_assertion's (client_id, jti)
	// pair as used, returning ErrAlreadyUsed if it was already consumed while
	// still valid. This bounds RFC 7523 private_key_jwt replay to a single use
	// per assertion, regardless of the assertion's own short lifetime.
	ConsumeClientAssertionJTI(clientID, jti string, expiresAt time.Time) error
}

type MemoryStore struct {
	mu         sync.Mutex
	clients    map[string]Client
	codes      map[string]AuthorizationCode
	refresh    map[string]RefreshToken
	consent    map[string]ConsentRequest
	assertions map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{clients: map[string]Client{}, codes: map[string]AuthorizationCode{}, refresh: map[string]RefreshToken{}, consent: map[string]ConsentRequest{}, assertions: map[string]time.Time{}}
}

func HashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *MemoryStore) SaveClient(client Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[client.ID] = client
	return nil
}

func (s *MemoryStore) ConsumeClientAssertionJTI(clientID, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, expiry := range s.assertions {
		if expiry.Before(now) {
			delete(s.assertions, key)
		}
	}
	key := clientID + "|" + jti
	if expiry, ok := s.assertions[key]; ok && expiry.After(now) {
		return ErrAlreadyUsed
	}
	s.assertions[key] = expiresAt
	return nil
}

func (s *MemoryStore) GetClient(id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	return client, nil
}

func (s *MemoryStore) SaveAuthorizationCode(code AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.ValueHash] = code
	return nil
}

func (s *MemoryStore) ConsumeAuthorizationCode(value string, now time.Time) (AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	code, ok := s.codes[hash]
	if !ok || code.ExpiresAt.Before(now) {
		return AuthorizationCode{}, ErrNotFound
	}
	if code.Used {
		return AuthorizationCode{}, ErrAlreadyUsed
	}
	code.Used = true
	s.codes[hash] = code
	return code, nil
}

func (s *MemoryStore) SaveRefreshToken(token RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token.ValueHash] = token
	return nil
}

func (s *MemoryStore) ConsumeRefreshToken(value string, now time.Time) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	token, ok := s.refresh[hash]
	if !ok || token.ExpiresAt.Before(now) || token.Revoked {
		return RefreshToken{}, ErrNotFound
	}
	if token.Used {
		return RefreshToken{}, ErrAlreadyUsed
	}
	token.Used = true
	s.refresh[hash] = token
	return token, nil
}

func (s *MemoryStore) RevokeRefreshToken(value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	token, ok := s.refresh[hash]
	if !ok {
		return ErrNotFound
	}
	token.Revoked = true
	s.refresh[hash] = token
	return nil
}

func (s *MemoryStore) SaveConsentRequest(request ConsentRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consent[request.ValueHash] = request
	return nil
}

func (s *MemoryStore) ConsumeConsentRequest(value string, now time.Time) (ConsentRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(value)
	request, ok := s.consent[hash]
	if !ok || request.ExpiresAt.Before(now) {
		return ConsentRequest{}, ErrNotFound
	}
	delete(s.consent, hash)
	return request, nil
}
