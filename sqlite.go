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
    expires_at     INTEGER NOT NULL,
    user_id        TEXT NOT NULL DEFAULT '',
    token_id       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS smeldr_oauth_tokens (
    token      TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    resource   TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    user_id    TEXT NOT NULL DEFAULT '',
    token_id   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS smeldr_oauth_refresh_tokens (
    token      TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0,
    user_id    TEXT NOT NULL DEFAULT '',
    token_id   TEXT NOT NULL DEFAULT ''
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
	// sql.Open cannot fail here: "sqlite" is registered by this package's own
	// import of modernc.org/sqlite, and that driver does not implement
	// driver.DriverContext, so the DSN is not read until the first query. A
	// bad path fails at that query (the migrations below).
	db, _ := sql.Open("sqlite", path)
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
	if err := migrateAddSubjectColumns(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("oauth: migrate subject columns: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// — AuthCode —

func (s *SQLiteStore) SaveCode(ctx context.Context, c AuthCode) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO smeldr_oauth_codes (code, client_id, redirect_uri, scope, code_challenge, resource, expires_at, user_id, token_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Code, c.ClientID, c.RedirectURI, c.Scope, c.CodeChallenge, c.Resource, c.ExpiresAt.Unix(), c.UserID, c.TokenID,
	)
	return err
}

func (s *SQLiteStore) GetCode(ctx context.Context, code string) (AuthCode, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT code, client_id, redirect_uri, scope, code_challenge, resource, expires_at, user_id, token_id
		 FROM smeldr_oauth_codes WHERE code = ?`, code,
	)
	var c AuthCode
	var expiresUnix int64
	if err := row.Scan(&c.Code, &c.ClientID, &c.RedirectURI, &c.Scope, &c.CodeChallenge, &c.Resource, &expiresUnix, &c.UserID, &c.TokenID); err != nil {
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
		`INSERT INTO smeldr_oauth_tokens (token, client_id, scope, resource, expires_at, user_id, token_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.Token, t.ClientID, t.Scope, t.Resource, t.ExpiresAt.Unix(), t.UserID, t.TokenID,
	)
	return err
}

func (s *SQLiteStore) GetToken(ctx context.Context, token string) (AccessToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token, client_id, scope, resource, expires_at, user_id, token_id
		 FROM smeldr_oauth_tokens WHERE token = ?`, token,
	)
	var t AccessToken
	var expiresUnix int64
	if err := row.Scan(&t.Token, &t.ClientID, &t.Scope, &t.Resource, &expiresUnix, &t.UserID, &t.TokenID); err != nil {
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
	return saveRefreshToken(ctx, s.db, t)
}

// refreshExec is what saveRefreshToken writes with: the database or a
// transaction.
type refreshExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func saveRefreshToken(ctx context.Context, db refreshExec, t RefreshToken) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO smeldr_oauth_refresh_tokens (token, client_id, scope, expires_at, user_id, token_id) VALUES (?, ?, ?, ?, ?, ?)`,
		t.Token, t.ClientID, t.Scope, unixOrZero(t.ExpiresAt), t.UserID, t.TokenID,
	)
	return err
}

// unixOrZero is t as Unix seconds, or 0 for the zero time.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// RotateRefreshToken removes old and saves next in one transaction. It
// reports [ErrRefreshTokenNotFound], and saves nothing, when old is not
// stored: it was used already, or never issued.
func (s *SQLiteStore) RotateRefreshToken(ctx context.Context, old string, next RefreshToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.ExecContext(ctx, `DELETE FROM smeldr_oauth_refresh_tokens WHERE token = ?`, old)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return ErrRefreshTokenNotFound
	}
	if err := saveRefreshToken(ctx, tx, next); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) GetRefreshToken(ctx context.Context, token string) (RefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token, client_id, scope, expires_at, user_id, token_id FROM smeldr_oauth_refresh_tokens WHERE token = ?`, token,
	)
	var t RefreshToken
	var expiresUnix int64
	if err := row.Scan(&t.Token, &t.ClientID, &t.Scope, &expiresUnix, &t.UserID, &t.TokenID); err != nil {
		if err == sql.ErrNoRows {
			return RefreshToken{}, ErrRefreshTokenNotFound
		}
		return RefreshToken{}, err
	}
	if expiresUnix > 0 {
		t.ExpiresAt = time.Unix(expiresUnix, 0).UTC()
	}
	return t, nil
}

func (s *SQLiteStore) DeleteRefreshToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM smeldr_oauth_refresh_tokens WHERE token = ?`, token)
	return err
}

// — RegisteredClient (RegistrationStore) —

func (s *SQLiteStore) SaveRegisteredClient(ctx context.Context, c RegisteredClient) error {
	// encoding/json cannot fail on a []string, so the error is not checked.
	redirectURIs, _ := json.Marshal(c.RedirectURIs)
	_, err := s.db.ExecContext(ctx,
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
