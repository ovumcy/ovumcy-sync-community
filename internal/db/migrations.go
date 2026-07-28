package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"
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

	embedded, applied, err := migrationState(ctx, database)
	if err != nil {
		return err
	}

	for _, version := range embedded {
		if _, done := applied[version]; done {
			continue
		}

		sqlBytes, err := migrationFiles.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err) // codecov:ignore -- same //go:embed compile-time guarantee as migrationState's ReadDir call: a path just returned by ReadDir on this embedded filesystem cannot fail a subsequent ReadFile. Cannot occur in practice.
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

// migrationState reads both sides of the migration bookkeeping — the sorted
// migration filenames this build embeds, and the set schema_migrations records
// as applied — and refuses outright when the database holds a migration this
// build does not know about.
//
// Comparing the two as sets, rather than as counts, is what separates the two
// directions in which database and binary can disagree. A database *behind*
// the binary is missing embedded versions: the ordinary pending-migration
// state that `migrate` resolves. A database *ahead* of the binary records
// versions the binary cannot know, because a newer build applied them; no code
// in this build understands the schema now on disk. Counting cannot tell those
// apart — rows from a newer build only push the applied total further past the
// embedded one — so a downgraded binary read as ready and served traffic on a
// schema it does not understand.
func migrationState(ctx context.Context, database *sql.DB) ([]string, map[string]struct{}, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, nil, fmt.Errorf("read migrations: %w", err) // codecov:ignore -- migrationFiles is a //go:embed compile-time filesystem baked into the binary; ReadDir("migrations") on an embedded path that matched the embed directive at build time cannot fail at runtime. Cannot occur in practice.
	}

	embedded := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue // codecov:ignore -- the embed directive is "migrations/*.sql" (files only, non-recursive), and the real migrations/ directory (verified) holds no subdirectories, so ReadDir never yields a directory entry here. Kept as defensive code against a future migrations layout change rather than removed.
		}
		embedded = append(embedded, entry.Name())
	}
	sort.Strings(embedded)

	applied, err := appliedMigrations(ctx, database)
	if err != nil {
		return nil, nil, err
	}

	if err := refuseUnknownMigrations(embedded, applied); err != nil {
		return nil, nil, err
	}

	return embedded, applied, nil
}

// appliedMigrations reads the whole set of versions schema_migrations records
// as applied. Reading the set once, rather than asking about one version at a
// time, is what makes the comparison possible in both directions: a
// per-version lookup can only answer "is this embedded migration applied yet",
// never "does the database hold a migration this build has never heard of".
func appliedMigrations(ctx context.Context, database *sql.DB) (map[string]struct{}, error) {
	rows, err := database.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("list applied migrations: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	applied := make(map[string]struct{})
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err) // codecov:ignore -- the result set is a handful of short TEXT rows from this store's single sqlite connection, fully drained by the loop above; faulting the iteration itself, rather than the query or an individual scan (both covered), has no deterministic in-process trigger without a fake driver.
	}

	return applied, nil
}

// refuseUnknownMigrations reports the applied migrations this build does not
// embed. The refusal names them and carries nothing else out of
// schema_migrations: applied_at, and any column a later build adds to that
// table, never reach the message or the log line it becomes.
func refuseUnknownMigrations(embedded []string, applied map[string]struct{}) error {
	known := make(map[string]struct{}, len(embedded))
	for _, version := range embedded {
		known[version] = struct{}{}
	}

	var unknown []string
	for version := range applied {
		if _, ok := known[version]; !ok {
			unknown = append(unknown, version)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)

	return fmt.Errorf(
		"database schema is ahead of this binary: schema_migrations records migration(s) %s that this build does not embed; deploy the build that applied them, or restore the database backup taken before that upgrade",
		strings.Join(unknown, ", "),
	)
}

// schemaReady reports whether the database carries exactly the schema this
// build expects. It gates the serve path before any traffic is accepted, so it
// fails closed: a database ahead of this build is an error rather than a
// not-ready answer, because "not ready" points the operator at `migrate`, and
// no migration walks a schema backwards.
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

	embedded, applied, err := migrationState(ctx, database)
	if err != nil {
		return false, err
	}

	for _, version := range embedded {
		if _, done := applied[version]; !done {
			return false, nil
		}
	}

	return true, nil
}
