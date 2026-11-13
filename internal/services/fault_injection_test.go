package services

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

// openFileBackedTestStore opens a migrated store on a temp file and returns it
// together with the database path, so a test can reach the same database over a
// second raw connection for fault injection (see dropTable). The in-memory
// openTestStore cannot be reached by an independent connection, so error
// branches that need a mid-operation store failure use this instead.
func openFileBackedTestStore(t *testing.T) (*db.Store, string) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "sync-community-services-test.db")
	store, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return store, dbPath
}

// dropTable removes one table out from under a live store through a second
// connection to the same database file, simulating a persistent-store failure
// for exactly the paths that touch that table. The sqlite driver is registered
// transitively via internal/db.
func dropTable(t *testing.T, dbPath, table string) {
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

// failAccountsUpdates installs, through a second connection, a trigger that
// aborts every UPDATE on accounts while reads keep working. It isolates the
// write half of a lapse or reactivation signal: the account lookup and the
// in-transaction state read still succeed and only the UPDATE fails. Mirrors
// internal/db's identically-named helper (duplicated per this repo's
// per-package fault-injection-helper convention).
func failAccountsUpdates(t *testing.T, dbPath string) {
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
	if _, err := raw.Exec(`CREATE TRIGGER fail_accounts_update BEFORE UPDATE ON accounts BEGIN SELECT RAISE(ABORT, 'injected accounts update failure'); END`); err != nil {
		t.Fatalf("install accounts update trigger: %v", err)
	}
}
