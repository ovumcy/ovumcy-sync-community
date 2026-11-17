package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// TestStoreTransactionsTakeTheWriteLockAtBegin pins _txlock=immediate: an
// open Store transaction already holds the write lock before its first
// statement, so a second process cannot commit between its read and its write
// (which would fail it with SQLITE_BUSY_SNAPSHOT).
func TestStoreTransactionsTakeTheWriteLockAtBegin(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	other, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatalf("open second handle: %v", err)
	}
	t.Cleanup(func() {
		_ = other.Close()
	})

	_, err = other.ExecContext(ctx, `BEGIN IMMEDIATE`)
	if err == nil {
		_, _ = other.ExecContext(ctx, `ROLLBACK`)
		t.Fatal("a second writer began while a Store transaction was open: BeginTx did not take the write lock")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "busy") && !strings.Contains(strings.ToLower(err.Error()), "locked") {
		t.Fatalf("expected a busy/locked refusal, got %v", err)
	}
}
