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
		return fmt.Errorf("read migrations: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
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
			return fmt.Errorf("read migration %s: %w", version, err)
		}

		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", version, err)
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
			return fmt.Errorf("commit migration %s: %w", version, err)
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
		return false, fmt.Errorf("read migrations: %w", err)
	}

	expected := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			expected++
		}
	}

	var applied int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations`).Scan(&applied); err != nil {
		return false, fmt.Errorf("count applied migrations: %w", err)
	}

	return applied >= expected, nil
}
