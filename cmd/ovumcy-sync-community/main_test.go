package main

import (
	"context"
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
