package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore is a durable single-node Store implementation. It stores only
// hashes for bearer values and uses transactions for one-time consumption.
// Deployments with multiple auth-server replicas should use a shared database
// or provide a Store implementation backed by their enterprise database.
type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(databaseURL string) (*SQLiteStore, error) {
	if databaseURL == "" {
		return nil, errors.New("sqlite database URL is required")
	}
	db, err := sql.Open("sqlite", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	store := &SQLiteStore{db: db}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure sqlite store: %w", err)
	}
	if err := store.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) initialize() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL,
  token_endpoint_auth TEXT NOT NULL, secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorization_codes (
  value_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT NOT NULL,
  subject TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  value_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL, subject TEXT NOT NULL,
  scope TEXT NOT NULL, resource TEXT NOT NULL, expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL, revoked INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS consent_requests (
  value_hash TEXT PRIMARY KEY, request_json TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL
);`)
	if err != nil {
		return fmt.Errorf("initialize sqlite store: %w", err)
	}
	// Keep databases created before refresh-token families compatible.
	_, _ = s.db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT ''`)
	return nil
}

func (s *SQLiteStore) SaveClient(client Client) error {
	redirects, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO clients (id,name,redirect_uris,token_endpoint_auth,secret_hash)
VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, redirect_uris=excluded.redirect_uris,
token_endpoint_auth=excluded.token_endpoint_auth, secret_hash=excluded.secret_hash`,
		client.ID, client.Name, string(redirects), client.TokenEndpointAuth, client.SecretHash)
	return err
}

func (s *SQLiteStore) GetClient(id string) (Client, error) {
	var client Client
	var redirects string
	err := s.db.QueryRow(`SELECT id,name,redirect_uris,token_endpoint_auth,secret_hash FROM clients WHERE id=?`, id).
		Scan(&client.ID, &client.Name, &redirects, &client.TokenEndpointAuth, &client.SecretHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	if err := json.Unmarshal([]byte(redirects), &client.RedirectURIs); err != nil {
		return Client{}, fmt.Errorf("decode client redirect URIs: %w", err)
	}
	return client, nil
}

func (s *SQLiteStore) SaveAuthorizationCode(code AuthorizationCode) error {
	scope, err := json.Marshal(code.Scope)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO authorization_codes
(value_hash,client_id,redirect_uri,code_challenge,scope,resource,subject,nonce,expires_at,used)
VALUES (?,?,?,?,?,?,?,?,?,?)`, code.ValueHash, code.ClientID, code.RedirectURI, code.CodeChallenge,
		string(scope), code.Resource, code.Subject, code.Nonce, code.ExpiresAt.UnixNano(), boolInt(code.Used))
	return err
}

func (s *SQLiteStore) ConsumeAuthorizationCode(value string, now time.Time) (AuthorizationCode, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return AuthorizationCode{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var code AuthorizationCode
	var scope string
	var expires int64
	var used int
	err = tx.QueryRow(`SELECT client_id,redirect_uri,code_challenge,scope,resource,subject,nonce,expires_at,used
FROM authorization_codes WHERE value_hash=?`, HashSecret(value)).Scan(&code.ClientID, &code.RedirectURI,
		&code.CodeChallenge, &scope, &code.Resource, &code.Subject, &code.Nonce, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthorizationCode{}, ErrNotFound
	}
	if err != nil {
		return AuthorizationCode{}, err
	}
	code.ValueHash, code.ExpiresAt, code.Used = HashSecret(value), time.Unix(0, expires), used != 0
	if code.ExpiresAt.Before(now) {
		return AuthorizationCode{}, ErrNotFound
	}
	if code.Used {
		return AuthorizationCode{}, ErrAlreadyUsed
	}
	if err := json.Unmarshal([]byte(scope), &code.Scope); err != nil {
		return AuthorizationCode{}, err
	}
	if _, err := tx.Exec(`UPDATE authorization_codes SET used=1 WHERE value_hash=? AND used=0`, code.ValueHash); err != nil {
		return AuthorizationCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationCode{}, err
	}
	code.Used = true
	return code, nil
}

func (s *SQLiteStore) SaveRefreshToken(token RefreshToken) error {
	scope, err := json.Marshal(token.Scope)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO refresh_tokens
(value_hash,family_id,client_id,subject,scope,resource,expires_at,used,revoked) VALUES (?,?,?,?,?,?,?,?,?)`,
		token.ValueHash, token.FamilyID, token.ClientID, token.Subject, string(scope), token.Resource, token.ExpiresAt.UnixNano(),
		boolInt(token.Used), boolInt(token.Revoked))
	return err
}

func (s *SQLiteStore) ConsumeRefreshToken(value string, now time.Time) (RefreshToken, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return RefreshToken{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var token RefreshToken
	var scope string
	var expires int64
	var used, revoked int
	err = tx.QueryRow(`SELECT family_id,client_id,subject,scope,resource,expires_at,used,revoked
FROM refresh_tokens WHERE value_hash=?`, HashSecret(value)).Scan(&token.FamilyID, &token.ClientID, &token.Subject, &scope,
		&token.Resource, &expires, &used, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, err
	}
	token.ValueHash, token.ExpiresAt = HashSecret(value), time.Unix(0, expires)
	token.Used, token.Revoked = used != 0, revoked != 0
	if token.ExpiresAt.Before(now) || token.Revoked {
		return RefreshToken{}, ErrNotFound
	}
	if token.Used {
		return RefreshToken{}, ErrAlreadyUsed
	}
	if err := json.Unmarshal([]byte(scope), &token.Scope); err != nil {
		return RefreshToken{}, err
	}
	if _, err := tx.Exec(`UPDATE refresh_tokens SET used=1 WHERE value_hash=? AND used=0 AND revoked=0`, token.ValueHash); err != nil {
		return RefreshToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return RefreshToken{}, err
	}
	token.Used = true
	return token, nil
}

func (s *SQLiteStore) RevokeRefreshToken(value string) error {
	result, err := s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE value_hash=?`, HashSecret(value))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) RevokeRefreshFamily(value string) error {
	var familyID string
	if err := s.db.QueryRow(`SELECT family_id FROM refresh_tokens WHERE value_hash=?`, HashSecret(value)).Scan(&familyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if familyID == "" {
		_, err := s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE value_hash=?`, HashSecret(value))
		return err
	}
	_, err := s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE family_id=?`, familyID)
	return err
}

func (s *SQLiteStore) SaveConsentRequest(request ConsentRequest) error {
	data, err := json.Marshal(request.Request)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO consent_requests (value_hash,request_json,nonce,expires_at)
VALUES (?,?,?,?)`, request.ValueHash, string(data), request.Nonce, request.ExpiresAt.UnixNano())
	return err
}

func (s *SQLiteStore) ConsumeConsentRequest(value string, now time.Time) (ConsentRequest, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return ConsentRequest{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var request ConsentRequest
	var data string
	var expires int64
	err = tx.QueryRow(`SELECT request_json,nonce,expires_at FROM consent_requests WHERE value_hash=?`, HashSecret(value)).
		Scan(&data, &request.Nonce, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsentRequest{}, ErrNotFound
	}
	if err != nil {
		return ConsentRequest{}, err
	}
	request.ValueHash, request.ExpiresAt = HashSecret(value), time.Unix(0, expires)
	if request.ExpiresAt.Before(now) {
		return ConsentRequest{}, ErrNotFound
	}
	if err := json.Unmarshal([]byte(data), &request.Request); err != nil {
		return ConsentRequest{}, err
	}
	if _, err := tx.Exec(`DELETE FROM consent_requests WHERE value_hash=?`, request.ValueHash); err != nil {
		return ConsentRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return ConsentRequest{}, err
	}
	return request, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
