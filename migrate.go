package oauth

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

// migrateLegacyTableNames renames any forge_oauth_* tables that still exist in
// the database to their smeldr_oauth_* equivalents. It is called from
// [NewSQLiteStore] once at startup before the CREATE TABLE statements run.
//
// Only operates on SQLite databases (identified by the presence of
// sqlite_master). For other databases it returns nil immediately.
//
// Idempotency: if both the source (forge_oauth_*) and destination
// (smeldr_oauth_*) tables already exist the pair is skipped with a warning and
// remaining pairs are still processed. Re-running on an already-migrated DB is
// safe.
func migrateLegacyTableNames(ctx context.Context, db *sql.DB) error {
	pairs := [][2]string{
		{"forge_oauth_codes", "smeldr_oauth_codes"},
		{"forge_oauth_tokens", "smeldr_oauth_tokens"},
		{"forge_oauth_refresh_tokens", "smeldr_oauth_refresh_tokens"},
	}

	var dummy int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master`).Scan(&dummy); err != nil {
		return nil // not SQLite — skip silently
	}

	var toRename [][2]string
	for _, pair := range pairs {
		var srcN int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, pair[0],
		).Scan(&srcN); err != nil || srcN == 0 {
			continue // source doesn't exist — nothing to rename
		}
		var dstN int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, pair[1],
		).Scan(&dstN); err == nil && dstN > 0 {
			slog.Warn("oauth: legacy table migration skipped — destination already exists",
				"src", pair[0], "dst", pair[1])
			continue
		}
		toRename = append(toRename, pair)
	}
	if len(toRename) == 0 {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("oauth: migrate legacy tables: begin: %w", err)
	}

	for _, pair := range toRename {
		slog.Info("oauth: renaming legacy table", "from", pair[0], "to", pair[1])
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+pair[0]+` RENAME TO `+pair[1]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("oauth: migrate legacy tables: %s → %s: %w", pair[0], pair[1], err)
		}
	}
	return tx.Commit()
}
