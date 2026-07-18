package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func applyMigrations(ctx context.Context, database *sql.DB) error {
	if _, err := database.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);
`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err) // codecov:ignore -- migrationFiles is a //go:embed compile-time filesystem baked into the binary; ReadDir("migrations") on an embedded path that matched the embed directive at build time cannot fail at runtime. Cannot occur in practice.
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue // codecov:ignore -- the embed directive is "migrations/*.sql" (files only, non-recursive), and the real migrations/ directory (verified) holds no subdirectories, so ReadDir never yields a directory entry here. Kept as defensive code against a future migrations layout change rather than removed.
		}

		version := entry.Name()
		applied, err := migrationApplied(ctx, database, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		sqlBytes, err := migrationFiles.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err) // codecov:ignore -- same //go:embed compile-time guarantee as the ReadDir call above: a path just returned by ReadDir on this embedded filesystem cannot fail a subsequent ReadFile. Cannot occur in practice.
		}

		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err) // codecov:ignore -- the "ensure schema_migrations" statement above is this function's first database call, so a closed store or canceled context already fails there (TestApplyMigrationsAndSchemaReadyReturnErrorsOnClosedStore); reaching this later BeginTx with an already-failing connection needs a fake driver or a synchronized concurrent transaction holding the store's sole connection (SetMaxOpenConns(1)), which would be a timing-fragile test.
		}

		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", version, err)
		}

		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`,
			version,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err) // codecov:ignore -- on this store's single-connection sqlite (WAL, busy_timeout) a COMMIT whose statements all succeeded has no deterministically injectable in-process failure; needs a fake driver, the same deviation documented for DeleteAccount's and DeleteLapsedManagedAccount's commit branches in repositories.go.
		}
	}

	return nil
}

func migrationApplied(ctx context.Context, database *sql.DB, version string) (bool, error) {
	var exists int
	if err := database.QueryRowContext(
		ctx,
		`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`,
		version,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}

	return exists > 0, nil
}

func schemaReady(ctx context.Context, database *sql.DB) (bool, error) {
	var schemaMigrationsExists int
	if err := database.QueryRowContext(
		ctx,
		`SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&schemaMigrationsExists); err != nil {
		return false, fmt.Errorf("check schema_migrations table: %w", err)
	}
	if schemaMigrationsExists == 0 {
		return false, nil
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return false, fmt.Errorf("read migrations: %w", err) // codecov:ignore -- same //go:embed compile-time guarantee as applyMigrations' identical ReadDir call above. Cannot occur in practice.
	}

	expected := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			expected++
		}
	}

	var applied int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations`).Scan(&applied); err != nil {
		return false, fmt.Errorf("count applied migrations: %w", err) // codecov:ignore -- schema_migrations must already exist for this line to be reached (the sqlite_master existence check just above returns early otherwise), and a plain COUNT(1) with no column reference cannot fail for an existing, readable table; needs a fake driver to fault the query itself.
	}

	return applied >= expected, nil
}
