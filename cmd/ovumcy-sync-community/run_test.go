package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// blockedDBPath returns a DB_PATH whose parent directory can never be
// created: a regular file sits where a directory needs to go. db.Open calls
// os.MkdirAll(filepath.Dir(path), ...) before touching sqlite, so this is a
// portable, black-box way to reach the "open database" error branch in both
// runServe and runMigrate without modifying production code.
func blockedDBPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	return filepath.Join(blocker, "subdir", "community.sqlite")
}

func TestRunDefaultsToServeAndSurfacesConfigLoadErrors(t *testing.T) {
	// No args: run must default to "serve" rather than fail dispatch. An
	// invalid config value makes config.Load fail before the switch is even
	// reached, so this exercises both the "len(args) == 0" default-command
	// branch and the config.Load error-wrapping branch in one call.
	t.Setenv("MAX_BLOB_BYTES", "0")

	err := run(nil)
	if err == nil {
		t.Fatal("expected error for invalid MAX_BLOB_BYTES, got nil")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Fatalf("expected error wrapped with \"load config\", got %v", err)
	}
	if !strings.Contains(err.Error(), "MAX_BLOB_BYTES") {
		t.Fatalf("expected underlying MAX_BLOB_BYTES validation error, got %v", err)
	}
}

func TestRunDispatchesHealthcheckCommand(t *testing.T) {
	// Port 1 on loopback is a reserved port that is never listening in this
	// test environment, so the probe fails with an immediate connection
	// refusal rather than waiting out the healthcheck's timeout. This
	// exercises the "healthcheck" case in run's command switch without
	// starting a real server.
	t.Setenv("BIND_ADDR", "127.0.0.1:1")

	err := run([]string{"healthcheck"})
	if err == nil {
		t.Fatal("expected healthcheck against an unreachable port to fail")
	}
}

func TestRunServeFailsWhenDatabaseCannotBeOpened(t *testing.T) {
	t.Setenv("DB_PATH", blockedDBPath(t))

	err := run([]string{"serve"})
	if err == nil || !strings.Contains(err.Error(), "open database") {
		t.Fatalf("expected open database error, got %v", err)
	}
}

func TestRunMigrateFailsWhenDatabaseCannotBeOpened(t *testing.T) {
	t.Setenv("DB_PATH", blockedDBPath(t))

	err := run([]string{"migrate"})
	if err == nil || !strings.Contains(err.Error(), "open database") {
		t.Fatalf("expected open database error, got %v", err)
	}
}

// TestRunDispatchesPurgeLapsedAccountsCommand exercises the
// "purge-lapsed-accounts" case in run's command switch end to end: config is
// loaded once by run() (unlike healthcheck/serve/migrate, this command also
// needs args[1:] threaded through as its own flag set), the schema is
// migrated fresh, and the sweep reports zero examined against an empty
// database.
func TestRunDispatchesPurgeLapsedAccountsCommand(t *testing.T) {
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "community.sqlite"))

	if err := run([]string{"purge-lapsed-accounts", "-dry-run"}); err != nil {
		t.Fatalf("run purge-lapsed-accounts: %v", err)
	}
}

func TestRunRejectsUnknownCommandMentionsPurgeLapsedAccounts(t *testing.T) {
	err := run([]string{"unknown"})
	if err == nil || !strings.Contains(err.Error(), "purge-lapsed-accounts") {
		t.Fatalf("expected the unknown-command error to mention purge-lapsed-accounts, got %v", err)
	}
}
