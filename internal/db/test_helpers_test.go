package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return store
}

// newFileBackedTestStore opens a migrated store on a temp file and returns it
// together with the database path, so a test can open an independent raw
// connection to the same database for failure injection (see dropTable).
// Mirrors the internal/api fault-injection harness (see server_test.go),
// scoped to internal/db so repository/migration methods can be faulted
// directly without any HTTP plumbing.
func newFileBackedTestStore(t *testing.T) (*Store, string) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "sync-community-test.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open file-backed store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return store, dbPath
}

// dropTable removes one table out from under a live *Store through a second
// connection to the same database file, simulating a persistent-store
// failure for exactly the repository/migration methods that touch that
// table. Every other table keeps working, so the targeted call reaches the
// method's generic error-wrapping branch instead of failing earlier.
func dropTable(t *testing.T, dbPath string, table string) {
	t.Helper()

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer func() {
		_ = raw.Close()
	}()

	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec("DROP TABLE " + table); err != nil { // #nosec G202 -- table is a test-fixture constant chosen by the test, never user input
		t.Fatalf("drop table %s: %v", table, err)
	}
}

// failDeletesOn makes every row delete on one table fail, through a second
// connection to the same database file, while the table stays readable. It
// reaches the "delete ... rows" error branches of a transaction that must first
// read that table (a session lookup), which dropTable would trip earlier.
func failDeletesOn(t *testing.T, dbPath string, table string) {
	t.Helper()

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer func() {
		_ = raw.Close()
	}()

	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec("CREATE TRIGGER fail_delete_" + table + " BEFORE DELETE ON " + table + " BEGIN SELECT RAISE(ABORT, 'delete refused'); END"); err != nil { // #nosec G202 -- table is a test-fixture constant chosen by the test, never user input
		t.Fatalf("create delete-failing trigger on %s: %v", table, err)
	}
}
