package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestIsStoreWideFailureSeparatesStoreFaultsFromRowFaults runs the classifier
// over real driver errors: a UNIQUE violation and a missing table are row- or
// statement-specific, a context expiry is store-wide.
func TestIsStoreWideFailureSeparatesStoreFaultsFromRowFaults(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE probe_unique (v TEXT UNIQUE)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO probe_unique (v) VALUES ('a')`); err != nil {
		t.Fatalf("seed probe row: %v", err)
	}
	_, uniqueErr := store.db.ExecContext(ctx, `INSERT INTO probe_unique (v) VALUES ('a')`)
	_, missingErr := store.db.ExecContext(ctx, `DELETE FROM no_such_table`)

	for name, err := range map[string]error{
		"unique":         uniqueErr,
		"missing table":  missingErr,
		"wrapped unique": fmt.Errorf("delete: %w", uniqueErr),
		"nil":            nil,
		"plain":          errors.New("boom"),
	} {
		if IsStoreWideFailure(err) {
			t.Errorf("%s: a row-specific error classified as store-wide", name)
		}
	}
	for name, err := range map[string]error{
		"canceled": context.Canceled,
		"deadline": fmt.Errorf("delete: %w", context.DeadlineExceeded),
		"busy":     errors.New("database is locked (5) (SQLITE_BUSY)"),
		"locked":   errors.New("database table is locked"),
		"readonly": errors.New("attempt to write a readonly database"),
		"ioerr":    errors.New("disk I/O error"),
		"full":     errors.New("database or disk is full"),
	} {
		if !IsStoreWideFailure(err) {
			t.Errorf("%s: a store-wide error classified as row-specific", name)
		}
	}
}
