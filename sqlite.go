package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)

const createTablesSQL = `
CREATE TABLE IF NOT EXISTS smeldr_oauth_codes (
    code           TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    scope          TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    resource       TEXT NOT NULL DEFAULT '',
    expires_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS smeldr_oauth_tokens (
    token      TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    resource   TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS smeldr_oauth_refresh_tokens (
    token     TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    scope     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS smeldr_oauth_registered_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
`

// SQLiteStore is a SQLite-backed implementation of [Store].
// It is safe for concurrent use. The three OAuth tables (smeldr_oauth_codes,
// smeldr_oauth_tokens, smeldr_oauth_refresh_tokens) are created automatically
// by [NewSQLiteStore] if they do not already exist.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite database at path and initialises
// the three OAuth tables. Use path ":memory:" for in-process testing.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("oauth: open sqlite %q: %w", path, err)
	}
	if err := migrateLegacyTableNames(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("oauth: migrate tables: %w", err)
	}
	if err := migrateAddResourceColumn(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("oauth: migrate resource column: %w", err)
	}
	if _, err := db.Exec(createTablesSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("oauth: create tables: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// — AuthCode —

func (s *SQLiteStore) SaveCode(ctx context.Context, c AuthCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO smeldr_oauth_codes (code, client_id, redirect_uri, scope, code_challenge, resource, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.Code, c.ClientID, c.RedirectURI, c.Scope, c.CodeChallenge, c.Resource, c.ExpiresAt.Unix(),
	)
	return err
}

func (s *SQLiteStore) GetCode(ctx context.Context, code string) (AuthCode, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT code, client_id, redirect_uri, scope, code_challenge, resource, expires_at
		 FROM smeldr_oauth_codes WHERE code = ?`, code,
	)
	var c AuthCode
	var expiresUnix int64
	if err := row.Scan(&c.Code, &c.ClientID, &c.RedirectURI, &c.Scope, &c.CodeChallenge, &c.Resource, &expiresUnix); err != nil {
		if err == sql.ErrNoRows {
			return AuthCode{}, ErrCodeNotFound
		}
		return AuthCode{}, err
	}
	c.ExpiresAt = time.Unix(expiresUnix, 0).UTC()
	return c, nil
}

func (s *SQLiteStore) DeleteCode(ctx context.Context, code string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM smeldr_oauth_codes WHERE code = ?`, code)
	return err
}

// — AccessToken —

func (s *SQLiteStore) SaveToken(ctx context.Context, t AccessToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO smeldr_oauth_tokens (token, client_id, scope, resource, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		t.Token, t.ClientID, t.Scope, t.Resource, t.ExpiresAt.Unix(),
	)
	return err
}

func (s *SQLiteStore) GetToken(ctx context.Context, token string) (AccessToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token, client_id, scope, resource, expires_at
		 FROM smeldr_oauth_tokens WHERE token = ?`, token,
	)
	var t AccessToken
	var expiresUnix int64
	if err := row.Scan(&t.Token, &t.ClientID, &t.Scope, &t.Resource, &expiresUnix); err != nil {
		if err == sql.ErrNoRows {
			return AccessToken{}, ErrTokenNotFound
		}
		return AccessToken{}, err
	}
	t.ExpiresAt = time.Unix(expiresUnix, 0).UTC()
	return t, nil
}

// — RefreshToken —

func (s *SQLiteStore) SaveRefreshToken(ctx context.Context, t RefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO smeldr_oauth_refresh_tokens (token, client_id, scope) VALUES (?, ?, ?)`,
		t.Token, t.ClientID, t.Scope,
	)
	return err
}

func (s *SQLiteStore) GetRefreshToken(ctx context.Context, token string) (RefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token, client_id, scope FROM smeldr_oauth_refresh_tokens WHERE token = ?`, token,
	)
	var t RefreshToken
	if err := row.Scan(&t.Token, &t.ClientID, &t.Scope); err != nil {
		if err == sql.ErrNoRows {
			return RefreshToken{}, ErrRefreshTokenNotFound
		}
		return RefreshToken{}, err
	}
	return t, nil
}

func (s *SQLiteStore) DeleteRefreshToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM smeldr_oauth_refresh_tokens WHERE token = ?`, token)
	return err
}

// — RegisteredClient (RegistrationStore) —

func (s *SQLiteStore) SaveRegisteredClient(ctx context.Context, c RegisteredClient) error {
	redirectURIs, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("oauth: marshal redirect_uris: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO smeldr_oauth_registered_clients (client_id, client_name, redirect_uris, created_at)
		 VALUES (?, ?, ?, ?)`,
		c.ClientID, c.ClientName, string(redirectURIs), c.CreatedAt.Unix(),
	)
	return err
}

func (s *SQLiteStore) GetRegisteredClient(ctx context.Context, clientID string) (RegisteredClient, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, client_name, redirect_uris, created_at
		 FROM smeldr_oauth_registered_clients WHERE client_id = ?`, clientID,
	)
	var c RegisteredClient
	var redirectURIs string
	var createdUnix int64
	if err := row.Scan(&c.ClientID, &c.ClientName, &redirectURIs, &createdUnix); err != nil {
		if err == sql.ErrNoRows {
			return RegisteredClient{}, ErrRegisteredClientNotFound
		}
		return RegisteredClient{}, err
	}
	if err := json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs); err != nil {
		return RegisteredClient{}, fmt.Errorf("oauth: unmarshal redirect_uris: %w", err)
	}
	c.CreatedAt = time.Unix(createdUnix, 0).UTC()
	return c, nil
}

// CountRegisteredClients returns the total number of registered clients.
// registerHandler calls this to enforce [MaxRegisteredClients] before
// accepting a new registration.
func (s *SQLiteStore) CountRegisteredClients(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM smeldr_oauth_registered_clients`).Scan(&n)
	return n, err
}
