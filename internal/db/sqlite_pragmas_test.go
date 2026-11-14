package db

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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
		{pragma: "secure_delete", want: "1"},
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

func TestOpenCreatesANewDatabaseFileOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	dbPath := filepath.Join(t.TempDir(), "fresh.sqlite")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE wal_probe (x INTEGER);`); err != nil {
		t.Fatalf("write to open the WAL: %v", err)
	}

	for _, path := range []string{dbPath, dbPath + "-wal"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("%s mode = %o, want 600", filepath.Base(path), mode)
		}
	}
}

func TestOpenReportsAnUncreatableDatabaseFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "create db file") {
		t.Fatalf("expected a directory as DB path to fail creating the file, got %v", err)
	}
}

func TestCreatePlainDBFileLeavesURIAndQueryPathsToSQLite(t *testing.T) {
	for _, path := range []string{"file:/nonexistent/dir/x.sqlite", "/nonexistent/dir/x.sqlite?mode=ro"} {
		if err := createPlainDBFileOwnerOnly(path); err != nil {
			t.Fatalf("createPlainDBFileOwnerOnly(%q) = %v, want nil", path, err)
		}
	}
}

func TestIsInMemoryPath(t *testing.T) {
	for path, want := range map[string]bool{
		":memory:":                        true,
		"file::memory:?cache=shared":      true,
		"file:sync?mode=memory":           true,
		"./data/sync.sqlite":              false,
		"file:/data/sync.sqlite?mode=rwc": false,
	} {
		if got := isInMemoryPath(path); got != want {
			t.Errorf("isInMemoryPath(%q) = %v, want %v", path, got, want)
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
