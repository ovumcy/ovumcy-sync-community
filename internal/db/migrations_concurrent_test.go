package db

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

func openFileStore(t *testing.T, dbPath string) *Store {
	t.Helper()
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func countMigrationRows(t *testing.T, store *Store) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	return n
}

// TestApplyMigrationSkipsAVersionAnotherRunnerRecorded: a runner whose pending
// list went stale, because another process applied the version since, skips
// it inside its own transaction instead of failing on the DDL.
func TestApplyMigrationSkipsAVersionAnotherRunnerRecorded(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sync.db")
	first := openFileStore(t, dbPath)
	if err := first.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("first runner: %v", err)
	}
	before := countMigrationRows(t, first)

	stale := openFileStore(t, dbPath)
	// 0011 is an ALTER TABLE ADD COLUMN: replaying it would fail on the
	// duplicate column.
	if err := applyMigration(context.Background(), stale.db, "0011_entitlement_signal_as_of.sql"); err != nil {
		t.Fatalf("expected the recorded version to be skipped, got %v", err)
	}
	if after := countMigrationRows(t, stale); after != before {
		t.Fatalf("expected schema_migrations unchanged, got %d -> %d", before, after)
	}
}

func TestConcurrentApplyMigrationsBothSucceed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sync.db")
	stores := []*Store{openFileStore(t, dbPath), openFileStore(t, dbPath)}

	var wg sync.WaitGroup
	errs := make([]error, len(stores))
	for i, store := range stores {
		wg.Add(1)
		go func(i int, store *Store) {
			defer wg.Done()
			errs[i] = store.ApplyMigrations(context.Background())
		}(i, store)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("runner %d: %v", i, err)
		}
	}
	ready, err := stores[0].SchemaReady(context.Background())
	if err != nil || !ready {
		t.Fatalf("expected the schema ready after both runners, got ready=%v err=%v", ready, err)
	}
}
