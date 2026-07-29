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

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatalf("columnExists(%q, %q): %v", table, column, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("columnExists(%q, %q): scan: %v", table, column, err)
		}
		if name == column {
			return true
		}
	}
	return false
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

func TestMigrateAddResourceColumn_freshDB(t *testing.T) {
	store, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	for _, table := range []string{"smeldr_oauth_codes", "smeldr_oauth_tokens"} {
		if !columnExists(t, store.db, table, "resource") {
			t.Errorf("expected %q to have a resource column", table)
		}
	}
}

func TestMigrateAddResourceColumn_existingTablesWithoutColumn(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Simulate a pre-A227 database: tables exist, no resource column.
	_, err = db.Exec(`
		CREATE TABLE smeldr_oauth_codes (code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, scope TEXT, code_challenge TEXT, expires_at INTEGER);
		CREATE TABLE smeldr_oauth_tokens (token TEXT PRIMARY KEY, client_id TEXT, scope TEXT, expires_at INTEGER);
	`)
	if err != nil {
		t.Fatalf("create pre-A227 tables: %v", err)
	}

	if err := migrateAddResourceColumn(context.Background(), db); err != nil {
		t.Fatalf("migrateAddResourceColumn: %v", err)
	}

	for _, table := range []string{"smeldr_oauth_codes", "smeldr_oauth_tokens"} {
		if !columnExists(t, db, table, "resource") {
			t.Errorf("expected %q to have a resource column after migration", table)
		}
	}

	// Existing rows must not be broken by the new NOT NULL column (DEFAULT '').
	if _, err := db.Exec(
		`INSERT INTO smeldr_oauth_codes (code, client_id, redirect_uri, scope, code_challenge, expires_at)
		 VALUES ('c1', 'client', 'uri', 'scope', 'chal', 0)`,
	); err != nil {
		t.Errorf("insert without resource after migration: %v", err)
	}
}

func TestMigrateAddResourceColumn_idempotent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE smeldr_oauth_codes (code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT, scope TEXT, code_challenge TEXT, expires_at INTEGER);
		CREATE TABLE smeldr_oauth_tokens (token TEXT PRIMARY KEY, client_id TEXT, scope TEXT, expires_at INTEGER);
	`)
	if err != nil {
		t.Fatalf("create pre-A227 tables: %v", err)
	}

	ctx := context.Background()
	if err := migrateAddResourceColumn(ctx, db); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call: column already exists — must not error (ALTER TABLE ADD
	// COLUMN on an already-migrated table would otherwise fail).
	if err := migrateAddResourceColumn(ctx, db); err != nil {
		t.Fatalf("second call: %v", err)
	}
}

func TestMigrateAddResourceColumn_nonSQLite(t *testing.T) {
	// A DB handle with no sqlite_master (simulated via a closed connection)
	// must return nil rather than erroring — mirrors migrateLegacyTableNames's
	// own non-SQLite short-circuit.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // closed — queries against it fail, simulating "not SQLite"

	if err := migrateAddResourceColumn(context.Background(), db); err != nil {
		t.Errorf("expected nil for a non-queryable DB, got %v", err)
	}
}
