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

// dropAccountsLapsedAtColumn removes accounts.lapsed_at out from under a
// live store through a second connection, leaving the accounts table (and
// every other column) otherwise intact. This isolates a store-failure in
// exactly the lapse-marker methods (SetAccountLapsed, ClearAccountLapse,
// etc.) that name lapsed_at directly, without disturbing FindAccountByID's
// own column list (which never selects lapsed_at) or any other account
// field — so the account-lookup half of a lapse-signal call still succeeds
// and only the subsequent write fails. Mirrors internal/db's identically
// -named test helper (duplicated per this repo's existing per-package
// fault-injection-helper convention rather than shared across packages).
func dropAccountsLapsedAtColumn(t *testing.T, dbPath string) {
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
	if _, err := raw.Exec(`ALTER TABLE accounts DROP COLUMN lapsed_at`); err != nil {
		t.Fatalf("drop accounts.lapsed_at column: %v", err)
	}
}
