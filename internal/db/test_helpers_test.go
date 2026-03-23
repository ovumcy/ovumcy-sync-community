package db

import (
	"context"
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
