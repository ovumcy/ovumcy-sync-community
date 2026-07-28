package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

func TestShutdownSignalReturnsChannel(t *testing.T) {
	if shutdownSignal() == nil {
		t.Fatal("expected shutdown signal channel")
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}

func TestRunServeRequiresInitializedSchema(t *testing.T) {
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "community.sqlite"))

	err := run([]string{"serve"})
	if err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("expected migrate guidance when schema is missing, got %v", err)
	}
}

// TestRunServeRefusesADatabaseAheadOfThisBuild pins the operator-facing half
// of the fail-closed rule that docs/self-hosting.md documents: rolling the
// binary back onto a database a newer build already migrated must abort before
// any listener opens, naming the migration this build does not embed, rather
// than serve traffic against a schema it cannot interpret.
func TestRunServeRefusesADatabaseAheadOfThisBuild(t *testing.T) {
	const futureMigration = "9999_applied_by_a_newer_build.sql"

	dbPath := filepath.Join(t.TempDir(), "community.sqlite")
	t.Setenv("DB_PATH", dbPath)

	if err := run([]string{"migrate"}); err != nil {
		t.Fatalf("run migrate: %v", err)
	}

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`,
		futureMigration,
	); err != nil {
		t.Fatalf("record a migration this build does not embed: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw sqlite: %v", err)
	}

	err = run([]string{"serve"})
	if err == nil {
		t.Fatal("expected serve to refuse a database ahead of this build")
	}
	if !strings.Contains(err.Error(), "ahead of this binary") {
		t.Fatalf("expected a schema-ahead refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), futureMigration) {
		t.Fatalf("expected the refusal to name %s, got %v", futureMigration, err)
	}
	if strings.Contains(err.Error(), "run `ovumcy-sync-community migrate`") {
		t.Fatalf("expected no migrate guidance for a database that is ahead, got %v", err)
	}
}

func TestRunMigrateInitializesSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "community.sqlite")
	t.Setenv("DB_PATH", dbPath)

	if err := run([]string{"migrate"}); err != nil {
		t.Fatalf("run migrate: %v", err)
	}

	store, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	ready, err := store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("schema ready: %v", err)
	}
	if !ready {
		t.Fatal("expected migrated schema to be ready")
	}
}
