package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestConnectionPragmasSurviveConnectionRecycling pins that every connection
// the pool dials runs with foreign keys on, a busy timeout and WAL, not only
// the first one: SetConnMaxLifetime retires connections, and a pragma applied
// once by Exec would be lost on the replacement. The directory name carries a
// space, '%' and '#' so the DSN built from the path is exercised with the
// characters a configured DB_PATH may contain.
func TestConnectionPragmasSurviveConnectionRecycling(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data dir %41 #1", "sync-community-test.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	ctx := context.Background()

	// cache_size is per-connection; a value only the first connection holds
	// proves the later reads ran on a freshly dialed one.
	if _, err := store.db.ExecContext(ctx, `PRAGMA cache_size = -1234;`); err != nil {
		t.Fatalf("mark first connection: %v", err)
	}

	store.db.SetConnMaxLifetime(time.Nanosecond)
	time.Sleep(time.Millisecond)

	var cacheSize int
	if err := store.db.QueryRowContext(ctx, `PRAGMA cache_size;`).Scan(&cacheSize); err != nil {
		t.Fatalf("read cache_size: %v", err)
	}
	if cacheSize == -1234 {
		t.Fatal("expected a recycled connection, still on the first one")
	}
	if closed := store.db.Stats().MaxLifetimeClosed; closed == 0 {
		t.Fatal("expected the pool to close a connection for exceeding its lifetime")
	}

	for _, tc := range []struct {
		pragma string
		want   string
	}{
		{pragma: "foreign_keys", want: "1"},
		{pragma: "busy_timeout", want: "5000"},
		{pragma: "journal_mode", want: "wal"},
	} {
		var got string
		if err := store.db.QueryRowContext(ctx, "PRAGMA "+tc.pragma+";").Scan(&got); err != nil { // #nosec G202 -- pragma names are test-table constants
			t.Fatalf("read %s: %v", tc.pragma, err)
		}
		if !strings.EqualFold(got, tc.want) {
			t.Fatalf("PRAGMA %s on a recycled connection = %q, want %q", tc.pragma, got, tc.want)
		}
	}
}

func TestSQLiteDSNAppendsPragmasAfterAnExistingQuery(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: `C:\data dir\sync.sqlite`, want: `C:\data dir\sync.sqlite?` + connectionPragmas},
		{path: ":memory:", want: ":memory:?" + connectionPragmas},
		{path: "file:/data/sync.sqlite?mode=rwc", want: "file:/data/sync.sqlite?mode=rwc&" + connectionPragmas},
	} {
		if got := sqliteDSN(tc.path); got != tc.want {
			t.Fatalf("sqliteDSN(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
