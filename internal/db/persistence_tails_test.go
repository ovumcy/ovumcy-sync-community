package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestErasingAnAccountTruncatesTheWAL(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := store.CreateAccount(ctx, models.Account{
		ID: "managed-1", Login: "managed:one", PasswordHash: "x", RecoveryCodeHash: "y",
		Mode: "managed", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if info, err := os.Stat(dbPath + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("expected a non-empty -wal before the erase, got %v / %v", info, err)
	}

	if err := store.DeleteManagedAccount(ctx, "managed-1"); err != nil {
		t.Fatalf("delete managed account: %v", err)
	}
	info, err := os.Stat(dbPath + "-wal")
	if err != nil {
		t.Fatalf("stat wal: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("-wal holds %d bytes after the erase, want 0 (truncated)", info.Size())
	}
}

// TestDeletingALapsedAccountLeavesTheCheckpointToTheSweep pins that the
// per-account lapsed delete does not checkpoint: the sweep checkpoints once
// per page instead.
func TestDeletingALapsedAccountLeavesTheCheckpointToTheSweep(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := store.CreateAccount(ctx, models.Account{
		ID: "managed-1", Login: "managed:one", PasswordHash: "x", RecoveryCodeHash: "y",
		Mode: "managed", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := store.SetAccountLapsed(ctx, "managed-1", now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("lapse account: %v", err)
	}
	if err := store.DeleteLapsedManagedAccount(ctx, "managed-1", now.Add(-time.Hour)); err != nil {
		t.Fatalf("delete lapsed account: %v", err)
	}
	if info, err := os.Stat(dbPath + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("expected the -wal untouched by the per-account delete, got %v / %v", info, err)
	}
}

func TestCheckpointAfterEraseNeverFailsAndLogsOnlyTheErrorClass(t *testing.T) {
	buf := captureLog(t)
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = store.Close()
	store.CheckpointAfterErase(context.Background())
	got := buf.String()
	if !strings.Contains(got, "wal checkpoint after erase failed: ") {
		t.Fatalf("expected a failure log line, got %q", got)
	}
	if strings.Contains(got, "closed") {
		t.Fatalf("log must carry the error class only, got %q", got)
	}
}

func TestCheckpointAfterEraseReportsABlockedCheckpoint(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	if _, err := store.CreateAccount(ctx, models.Account{
		ID: "a1", Login: "a1", PasswordHash: "x", RecoveryCodeHash: "y",
		Mode: "self_hosted", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer func() { _ = raw.Close() }()
	tx, err := raw.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM accounts`).Scan(&n); err != nil {
		t.Fatalf("read: %v", err)
	}
	// A write after the reader's snapshot keeps the WAL ahead of it.
	if _, err := store.CreateAccount(ctx, models.Account{
		ID: "a2", Login: "a2", PasswordHash: "x", RecoveryCodeHash: "y",
		Mode: "self_hosted", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create second account: %v", err)
	}

	buf := captureLog(t)
	store.CheckpointAfterErase(ctx)
	if !strings.Contains(buf.String(), "blocked by a concurrent connection") {
		t.Fatalf("expected the blocked-checkpoint log line, got %q", buf.String())
	}
}

func TestCreateAccountWithSessionIsAtomic(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	account := models.Account{ID: "acc-1", Login: "one", PasswordHash: "x", RecoveryCodeHash: "y", Mode: "self_hosted", CreatedAt: now}
	session := models.Session{ID: "s1", AccountID: "acc-1", TokenHash: "t1", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateAccountWithSession(ctx, account, session); err != nil {
		t.Fatalf("create: %v", err)
	}

	dup := models.Account{ID: "acc-2", Login: "one", PasswordHash: "x", RecoveryCodeHash: "y", Mode: "self_hosted", CreatedAt: now}
	dupSession := models.Session{ID: "s2", AccountID: "acc-2", TokenHash: "t2", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateAccountWithSession(ctx, dup, dupSession); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate login = %v, want ErrConflict", err)
	}

	// A session that cannot insert (duplicate session id) must roll back the account.
	clash := models.Account{ID: "acc-3", Login: "three", PasswordHash: "x", RecoveryCodeHash: "y", Mode: "self_hosted", CreatedAt: now}
	clashSession := models.Session{ID: "s1", AccountID: "acc-3", TokenHash: "t3", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateAccountWithSession(ctx, clash, clashSession); err == nil || !strings.Contains(err.Error(), "insert session") {
		t.Fatalf("clashing session = %v, want an insert session error", err)
	}
	var accounts int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM accounts WHERE id IN ('acc-2','acc-3')`).Scan(&accounts); err != nil {
		t.Fatalf("count: %v", err)
	}
	if accounts != 0 {
		t.Fatalf("%d account rows survived a failed registration, want 0", accounts)
	}
}

func TestCreateAccountWithSessionFailsOnAClosedStore(t *testing.T) {
	store := openTestStore(t)
	_ = store.Close()
	err := store.CreateAccountWithSession(context.Background(), models.Account{}, models.Session{})
	if err == nil || !strings.Contains(err.Error(), "begin create account") {
		t.Fatalf("closed store = %v, want a begin error", err)
	}
}

func TestPlainDBFilenameDropsTheSlashBeforeAWindowsDriveLetter(t *testing.T) {
	saved := windowsURIPaths
	t.Cleanup(func() { windowsURIPaths = saved })

	cases := []struct {
		path, windows, posix string
	}{
		{"file:///C:/data/sync.db", "C:/data/sync.db", "/C:/data/sync.db"},
		{"file:/d:/data/sync.db?mode=rwc", "d:/data/sync.db", "/d:/data/sync.db"},
		{"file://localhost/C:/data/sync.db", "C:/data/sync.db", "/C:/data/sync.db"},
		{"file:///C%3A/data/sync.db", "C:/data/sync.db", "/C:/data/sync.db"},
		{"file:///1:/data/sync.db", "/1:/data/sync.db", "/1:/data/sync.db"},
		{"file:///C/data/sync.db", "/C/data/sync.db", "/C/data/sync.db"},
		{"/C:/data/sync.db", "C:/data/sync.db", "/C:/data/sync.db"},
		{"C:/data/sync.db", "C:/data/sync.db", "C:/data/sync.db"},
	}
	for _, windows := range []bool{true, false} {
		windowsURIPaths = windows
		for _, c := range cases {
			want := c.posix
			if windows {
				want = c.windows
			}
			if got := plainDBFilename(c.path); got != want {
				t.Errorf("windows=%v plainDBFilename(%q) = %q, want %q", windows, c.path, got, want)
			}
		}
	}
}

func TestPlainDBFilename(t *testing.T) {
	for path, want := range map[string]string{
		"/data/sync.sqlite":               "/data/sync.sqlite",
		"/data/sync.sqlite?mode=rwc":      "/data/sync.sqlite",
		"file:/data/sync.sqlite?mode=rwc": "/data/sync.sqlite",
		"file:rel/sync.sqlite":            "rel/sync.sqlite",
		"file:///data/sync.sqlite":        "/data/sync.sqlite",
		"file://localhost/data/sync.db":   "/data/sync.db",
		"file:/data/with%20space.sqlite":  "/data/with space.sqlite",
		"file:/data/bad%zzescape.sqlite":  "/data/bad%zzescape.sqlite",
	} {
		if got := plainDBFilename(path); got != want {
			t.Errorf("plainDBFilename(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestOpenPreCreatesAFileURIDatabaseOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes and file: URI path forms")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "uri.sqlite")
	uri := "file:" + filepath.ToSlash(target) + "?mode=rwc"
	store, err := Open(uri)
	if err != nil {
		t.Fatalf("open %q: %v", uri, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("db file mode = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "file:") {
			t.Fatalf("stray %q created next to the database", entry.Name())
		}
	}
}
