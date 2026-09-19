package oauth

import (
	"context"
	"testing"
	"time"
)

func TestNewSQLiteStore_OpenError(t *testing.T) {
	// A directory path is not a valid SQLite database file — the first real
	// query against it (inside migrateLegacyTableNames) fails, exercising
	// NewSQLiteStore's wrapped-error return path.
	if _, err := NewSQLiteStore(t.TempDir()); err == nil {
		t.Fatal("expected error opening a directory as a SQLite database, got nil")
	}
}

func TestGetCode_NotFound(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.GetCode(context.Background(), "nonexistent"); err != ErrCodeNotFound {
		t.Errorf("GetCode: err = %v, want ErrCodeNotFound", err)
	}
}

func TestGetToken_NotFound(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.GetToken(context.Background(), "nonexistent"); err != ErrTokenNotFound {
		t.Errorf("GetToken: err = %v, want ErrTokenNotFound", err)
	}
}

func TestGetRefreshToken_NotFound(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.GetRefreshToken(context.Background(), "nonexistent"); err != ErrRefreshTokenNotFound {
		t.Errorf("GetRefreshToken: err = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestDeleteRefreshToken(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	tok := RefreshToken{Token: "rt-1", ClientID: "https://client.example.com", Scope: "mcp"}
	if err := store.SaveRefreshToken(ctx, tok); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, tok.Token); err != nil {
		t.Fatalf("GetRefreshToken before delete: %v", err)
	}

	if err := store.DeleteRefreshToken(ctx, tok.Token); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, tok.Token); err != ErrRefreshTokenNotFound {
		t.Errorf("GetRefreshToken after delete: err = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestGetCode_ScanError(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Insert a row with a non-integer expires_at — Scan into int64 fails,
	// a distinct branch from the sql.ErrNoRows case.
	if _, err := store.db.Exec(
		`INSERT INTO smeldr_oauth_codes (code, client_id, redirect_uri, scope, code_challenge, resource, expires_at)
		 VALUES ('bad-code', 'client', 'uri', 'scope', 'chal', '', 'not-an-integer')`,
	); err != nil {
		t.Fatalf("insert malformed row: %v", err)
	}

	if _, err := store.GetCode(context.Background(), "bad-code"); err == nil || err == ErrCodeNotFound {
		t.Errorf("GetCode: err = %v, want a scan error (not ErrCodeNotFound, not nil)", err)
	}
}

func TestGetToken_ScanError(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.db.Exec(
		`INSERT INTO smeldr_oauth_tokens (token, client_id, scope, resource, expires_at)
		 VALUES ('bad-token', 'client', 'scope', '', 'not-an-integer')`,
	); err != nil {
		t.Fatalf("insert malformed row: %v", err)
	}

	if _, err := store.GetToken(context.Background(), "bad-token"); err == nil || err == ErrTokenNotFound {
		t.Errorf("GetToken: err = %v, want a scan error (not ErrTokenNotFound, not nil)", err)
	}
}

func TestSQLiteStore_CodeRoundTrip(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	c := AuthCode{
		Code:          "c-1",
		ClientID:      "https://client.example.com",
		RedirectURI:   "https://client.example.com/callback",
		Scope:         "mcp",
		CodeChallenge: "challenge",
		Resource:      "https://server.example.com/mcp",
		ExpiresAt:     time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second),
	}
	if err := store.SaveCode(ctx, c); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	got, err := store.GetCode(ctx, c.Code)
	if err != nil {
		t.Fatalf("GetCode: %v", err)
	}
	if got.ClientID != c.ClientID || !got.ExpiresAt.Equal(c.ExpiresAt) {
		t.Errorf("GetCode round-trip mismatch: got %+v, want %+v", got, c)
	}
	if err := store.DeleteCode(ctx, c.Code); err != nil {
		t.Fatalf("DeleteCode: %v", err)
	}
	if _, err := store.GetCode(ctx, c.Code); err != ErrCodeNotFound {
		t.Errorf("GetCode after delete: err = %v, want ErrCodeNotFound", err)
	}
}
