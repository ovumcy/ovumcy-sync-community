package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

// TestIsRowSpecificFailureSkipsOnlyRowFaults runs the classifier over real
// driver errors: a UNIQUE violation is row-specific; a missing table, a closed
// store, a context expiry, the store-wide SQLite codes and an unknown error are
// not, so the sweep keeps braking on them.
func TestIsRowSpecificFailureSkipsOnlyRowFaults(t *testing.T) {
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
		"wrapped unique": fmt.Errorf("delete: %w", uniqueErr),
		"fk message":     errors.New("FOREIGN KEY constraint failed"),
		"mismatch":       errors.New("datatype mismatch"),
	} {
		if !IsRowSpecificFailure(err) {
			t.Errorf("%s: a row-specific error not classified as row-specific", name)
		}
	}
	for name, err := range map[string]error{
		"nil":           nil,
		"missing table": missingErr,
		"closed store":  sql.ErrConnDone,
		"canceled":      context.Canceled,
		"deadline":      fmt.Errorf("delete: %w", context.DeadlineExceeded),
		"busy":          errors.New("database is locked (5) (SQLITE_BUSY)"),
		"readonly":      errors.New("attempt to write a readonly database"),
		"ioerr":         errors.New("disk I/O error"),
		"full":          errors.New("database or disk is full"),
		"plain":         errors.New("boom"),
	} {
		if IsRowSpecificFailure(err) {
			t.Errorf("%s: classified as row-specific, so the sweep would stop braking on it", name)
		}
	}
}
