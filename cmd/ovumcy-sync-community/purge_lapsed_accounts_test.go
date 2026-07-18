package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/config"
	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

const testLapsedAccountGracePeriod = 60 * 24 * time.Hour

// testConfigForDBPath returns a Config pointed at dbPath with the same
// defaults config.Load would produce, so runPurgeLapsedAccounts sees a
// realistic configuration the way main()'s run() dispatch hands it one
// (config is loaded once in run(), before the command switch — unlike the
// ovumcy-managed peer's gc-guest-accounts subcommand, which loads its own
// config internally).
func testConfigForDBPath(dbPath string) config.Config {
	return config.Config{
		BindAddr:                 ":8080",
		DBPath:                   dbPath,
		SessionTTL:               24 * time.Hour,
		MaxDevices:               5,
		MaxBlobBytes:             16 << 20,
		AuthRateLimitCount:       10,
		AuthRateLimitWindow:      time.Minute,
		LapsedAccountGracePeriod: testLapsedAccountGracePeriod,
	}
}

// seedLapsedManagedAccount opens dbPath directly, provisions a managed
// account via the same bridge service the production binary wires, and
// records its lapse lapsedAgo in the past. Unlike the ovumcy-managed peer's
// guest-account seeding (which has to backdate revoked_at via a raw
// connection because RevokeGrant only ever stamps "now"), SetAccountLapsed
// takes an explicit timestamp directly, so no raw-connection backdating
// step is needed here.
func seedLapsedManagedAccount(t *testing.T, dbPath string, accountID string, lapsedAgo time.Duration) {
	t.Helper()
	ctx := context.Background()

	store, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open seed store: %v", err)
	}
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	authService := services.NewAuthService(store, time.Hour)
	bridgeService := services.NewManagedBridgeService(store, authService)
	if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
		t.Fatalf("create managed session for %s: %v", accountID, err)
	}
	if err := store.SetAccountLapsed(ctx, accountID, time.Now().UTC().Add(-lapsedAgo)); err != nil {
		t.Fatalf("lapse %s: %v", accountID, err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}
}

// failingWriter is an io.Writer whose Write calls succeed up to failAfter
// times, then fail — used to deterministically exercise
// runPurgeLapsedAccounts's per-Fprintf error-propagation branches (the
// summary line vs. each deleted-account-id line), mirroring the
// ovumcy-managed peer's identically-named test double for gc-guest-accounts.
type failingWriter struct {
	failAfter int
	calls     int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.calls >= w.failAfter {
		return 0, errors.New("simulated write failure")
	}
	w.calls++
	return len(p), nil
}

func TestRunPurgeLapsedAccountsRejectsUnknownFlag(t *testing.T) {
	cfg := testConfigForDBPath(filepath.Join(t.TempDir(), "unused.sqlite"))

	var buf bytes.Buffer
	err := runPurgeLapsedAccounts(cfg, []string{"-bogus-flag"}, &buf)
	if err == nil {
		t.Fatal("expected a flag-parse error for an unknown flag")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output on a flag-parse failure, got %q", buf.String())
	}
}

func TestRunPurgeLapsedAccountsPropagatesDBOpenError(t *testing.T) {
	cfg := testConfigForDBPath(blockedDBPath(t))

	var buf bytes.Buffer
	err := runPurgeLapsedAccounts(cfg, nil, &buf)
	if err == nil || !strings.Contains(err.Error(), "open database") {
		t.Fatalf("expected an open-database error, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output on a db-open failure, got %q", buf.String())
	}
}

// TestRunPurgeLapsedAccountsPropagatesApplyMigrationsError marks migration
// 0001_init.sql as already applied without actually running it, so
// ApplyMigrations skips straight to 0003_managed_account_fields.sql (which
// ALTER TABLEs the accounts table 0001 would have created) and fails against
// the missing table.
func TestRunPurgeLapsedAccountsPropagatesApplyMigrationsError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fake-applied.sqlite")

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES ('0001_init.sql', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed fake-applied row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw connection: %v", err)
	}

	cfg := testConfigForDBPath(dbPath)

	var buf bytes.Buffer
	err = runPurgeLapsedAccounts(cfg, nil, &buf)
	if err == nil || !strings.Contains(err.Error(), "apply migrations") {
		t.Fatalf("expected an apply-migrations error, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output on an apply-migrations failure, got %q", buf.String())
	}
}

func TestRunPurgeLapsedAccountsReportsZeroOnEmptyDatabase(t *testing.T) {
	cfg := testConfigForDBPath(filepath.Join(t.TempDir(), "empty.sqlite"))

	var buf bytes.Buffer
	if err := runPurgeLapsedAccounts(cfg, nil, &buf); err != nil {
		t.Fatalf("runPurgeLapsedAccounts returned error: %v", err)
	}

	want := "lapsed_account_sweep_dry_run=false\nlapsed_account_sweep_examined=0\nlapsed_account_sweep_deleted=0\n"
	if got := buf.String(); got != want {
		t.Fatalf("output mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRunPurgeLapsedAccountsDryRunFlag(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dry-run.sqlite")
	const accountID = "purgecliaccount01"
	seedLapsedManagedAccount(t, dbPath, accountID, 90*24*time.Hour)

	cfg := testConfigForDBPath(dbPath)

	var buf bytes.Buffer
	if err := runPurgeLapsedAccounts(cfg, []string{"-dry-run"}, &buf); err != nil {
		t.Fatalf("runPurgeLapsedAccounts returned error: %v", err)
	}

	want := "lapsed_account_sweep_dry_run=true\nlapsed_account_sweep_examined=1\nlapsed_account_sweep_deleted=0\n"
	if got := buf.String(); got != want {
		t.Fatalf("output mismatch:\n got: %q\nwant: %q", got, want)
	}

	store, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = store.Close() }()
	if _, err := store.FindAccountByID(context.Background(), accountID); err != nil {
		t.Fatalf("expected the account to survive dry-run, got %v", err)
	}
}

func TestRunPurgeLapsedAccountsDeletesEligibleAccountEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "delete-e2e.sqlite")
	const accountID = "purgecliaccount01"
	seedLapsedManagedAccount(t, dbPath, accountID, 90*24*time.Hour)

	cfg := testConfigForDBPath(dbPath)

	var buf bytes.Buffer
	if err := runPurgeLapsedAccounts(cfg, nil, &buf); err != nil {
		t.Fatalf("runPurgeLapsedAccounts returned error: %v", err)
	}

	want := "lapsed_account_sweep_dry_run=false\nlapsed_account_sweep_examined=1\nlapsed_account_sweep_deleted=1\n" +
		"lapsed_account_sweep_deleted_account_id=" + accountID + "\n"
	if got := buf.String(); got != want {
		t.Fatalf("output mismatch:\n got: %q\nwant: %q", got, want)
	}

	store, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = store.Close() }()
	if _, err := store.FindAccountByID(context.Background(), accountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected the account gone, got %v", err)
	}
}

func TestRunPurgeLapsedAccountsLimitFlagBoundsExamined(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "limit.sqlite")
	seedLapsedManagedAccount(t, dbPath, "purgeclilimit0001", 90*24*time.Hour)
	seedLapsedManagedAccount(t, dbPath, "purgeclilimit0002", 91*24*time.Hour)

	cfg := testConfigForDBPath(dbPath)

	var buf bytes.Buffer
	if err := runPurgeLapsedAccounts(cfg, []string{"-limit=1"}, &buf); err != nil {
		t.Fatalf("runPurgeLapsedAccounts returned error: %v", err)
	}

	if !strings.Contains(buf.String(), "lapsed_account_sweep_examined=1\n") {
		t.Fatalf("expected -limit=1 to cap examined at 1, got %q", buf.String())
	}
}

// TestRunPurgeLapsedAccountsReportsPartialProgressOnRunError proves the
// "print progress before the error" convention (mirroring
// runReminderSweepLoop / gc-guest-accounts in the ovumcy-managed peer):
// dropping the sessions table after seeding makes the eligible account's
// delete fail, but the summary is still written and the process-level error
// still propagates.
func TestRunPurgeLapsedAccountsReportsPartialProgressOnRunError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "run-error.sqlite")
	const accountID = "purgecliaccount01"
	seedLapsedManagedAccount(t, dbPath, accountID, 90*24*time.Hour)

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.Exec(`DROP TABLE sessions`); err != nil {
		t.Fatalf("drop sessions table: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw connection: %v", err)
	}

	cfg := testConfigForDBPath(dbPath)

	var buf bytes.Buffer
	err = runPurgeLapsedAccounts(cfg, nil, &buf)
	if err == nil {
		t.Fatal("expected a run error when a child table is missing")
	}

	want := "lapsed_account_sweep_dry_run=false\nlapsed_account_sweep_examined=1\nlapsed_account_sweep_deleted=0\n"
	if got := buf.String(); got != want {
		t.Fatalf("expected partial progress to be reported before the error:\n got: %q\nwant: %q", got, want)
	}
}

func TestRunPurgeLapsedAccountsPropagatesSummaryWriteError(t *testing.T) {
	cfg := testConfigForDBPath(filepath.Join(t.TempDir(), "write-fail-summary.sqlite"))

	writer := &failingWriter{failAfter: 0}
	if err := runPurgeLapsedAccounts(cfg, nil, writer); err == nil {
		t.Fatal("expected a write error from the summary line")
	}
}

func TestRunPurgeLapsedAccountsPropagatesDeletedIDWriteError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "write-fail-id.sqlite")
	seedLapsedManagedAccount(t, dbPath, "purgecliaccount01", 90*24*time.Hour)
	cfg := testConfigForDBPath(dbPath)

	writer := &failingWriter{failAfter: 1}
	if err := runPurgeLapsedAccounts(cfg, nil, writer); err == nil {
		t.Fatal("expected a write error from the deleted-account-id line")
	}
}
