package oauth

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&n)
	if err != nil {
		t.Fatalf("tableExists(%q): %v", name, err)
	}
	return n > 0
}

func TestMigrateLegacyTableNames_freshDB(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	for _, name := range []string{"smeldr_oauth_codes", "smeldr_oauth_tokens", "smeldr_oauth_refresh_tokens"} {
		if !tableExists(t, store.db, name) {
			t.Errorf("expected table %q to exist", name)
		}
	}
	for _, name := range []string{"forge_oauth_codes", "forge_oauth_tokens", "forge_oauth_refresh_tokens"} {
		if tableExists(t, store.db, name) {
			t.Errorf("expected legacy table %q to not exist", name)
		}
	}
}

func TestMigrateLegacyTableNames_existingForge(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE forge_oauth_codes (code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, scope TEXT, code_challenge TEXT, expires_at INTEGER);
		CREATE TABLE forge_oauth_tokens (token TEXT PRIMARY KEY, client_id TEXT, scope TEXT, expires_at INTEGER);
		CREATE TABLE forge_oauth_refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT, scope TEXT);
	`)
	if err != nil {
		t.Fatalf("create legacy tables: %v", err)
	}

	if err := migrateLegacyTableNames(context.Background(), db); err != nil {
		t.Fatalf("migrateLegacyTableNames: %v", err)
	}

	for _, name := range []string{"smeldr_oauth_codes", "smeldr_oauth_tokens", "smeldr_oauth_refresh_tokens"} {
		if !tableExists(t, db, name) {
			t.Errorf("expected table %q to exist after migration", name)
		}
	}
	for _, name := range []string{"forge_oauth_codes", "forge_oauth_tokens", "forge_oauth_refresh_tokens"} {
		if tableExists(t, db, name) {
			t.Errorf("expected legacy table %q to be gone after migration", name)
		}
	}
}

func TestMigrateLegacyTableNames_idempotent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE forge_oauth_codes (code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, scope TEXT, code_challenge TEXT, expires_at INTEGER);
		CREATE TABLE forge_oauth_tokens (token TEXT PRIMARY KEY, client_id TEXT, scope TEXT, expires_at INTEGER);
		CREATE TABLE forge_oauth_refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT, scope TEXT);
	`)
	if err != nil {
		t.Fatalf("create legacy tables: %v", err)
	}

	ctx := context.Background()
	if err := migrateLegacyTableNames(ctx, db); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call: forge_* are gone; smeldr_* exist — must not error.
	if err := migrateLegacyTableNames(ctx, db); err != nil {
		t.Fatalf("second call: %v", err)
	}
}
