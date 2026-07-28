package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// futureMigrationVersion stands in for a migration a newer build introduced
// and applied. It sorts after every filename this build embeds, so it is the
// shape a real forward migration would have.
const futureMigrationVersion = "9999_applied_by_a_newer_build.sql"

// Readiness used to compare the *count* of applied migrations against the
// count of embedded ones (`applied >= expected`). Under that rule a
// downgraded binary — an older build carrying fewer embedded migrations —
// pointed at a database a newer build had already migrated reported ready and
// served traffic against a schema it does not understand. Every extra row in
// schema_migrations only pushed the count further past the threshold, so the
// further ahead the database was, the readier it looked.
//
// The tests below pin set semantics in both directions: the database being
// behind the binary stays an ordinary pending-migration state, while the
// database being ahead is a hard refusal that names the unknown migration.

func TestSchemaReadyRefusesADatabaseAheadOfTheBinary(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)

	ready, err := store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("schema ready on a fully migrated database: %v", err)
	}
	if !ready {
		t.Fatal("expected a fully migrated database to be ready before the unknown migration is recorded")
	}

	recordAppliedMigration(t, dbPath, futureMigrationVersion)

	ready, err = store.SchemaReady(context.Background())
	if err == nil {
		t.Fatalf("expected SchemaReady to refuse a database ahead of this build, got ready=%v", ready)
	}
	if ready {
		t.Fatal("expected ready=false alongside the refusal")
	}
	if !strings.Contains(err.Error(), "ahead of this binary") {
		t.Fatalf("expected a schema-ahead refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), futureMigrationVersion) {
		t.Fatalf("expected the refusal to name %s, got %v", futureMigrationVersion, err)
	}
}

func TestApplyMigrationsRefusesADatabaseAheadOfTheBinary(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)

	recordAppliedMigration(t, dbPath, futureMigrationVersion)

	err := store.ApplyMigrations(context.Background())
	if err == nil {
		t.Fatal("expected ApplyMigrations to refuse a database ahead of this build")
	}
	if !strings.Contains(err.Error(), "ahead of this binary") {
		t.Fatalf("expected a schema-ahead refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), futureMigrationVersion) {
		t.Fatalf("expected the refusal to name %s, got %v", futureMigrationVersion, err)
	}
}

// TestSchemaAheadRefusalNamesOnlyTheMigrationVersion guards the refusal's
// blast radius: the message identifies the migration by filename and carries
// nothing else out of the row. applied_at is operational metadata, and the
// same code path would happily interpolate any other column added to
// schema_migrations later.
func TestSchemaAheadRefusalNamesOnlyTheMigrationVersion(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)

	recordAppliedMigrationAt(t, dbPath, futureMigrationVersion, "2099-01-02T03:04:05Z")

	_, err := store.SchemaReady(context.Background())
	if err == nil {
		t.Fatal("expected SchemaReady to refuse a database ahead of this build")
	}
	if strings.Contains(err.Error(), "2099-01-02T03:04:05Z") {
		t.Fatalf("expected the refusal to carry no row data beyond the migration name, got %v", err)
	}
}

// TestSchemaReadyReportsPendingMigrationsWithoutRefusing is the other half of
// the distinction: a database *behind* this build is not a refusal, it is the
// ordinary "run migrate" state. Deleting a recorded row leaves schema_migrations
// short of the embedded set without touching the schema those migrations built.
func TestSchemaReadyReportsPendingMigrationsWithoutRefusing(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)

	forgetAppliedMigration(t, dbPath, "0008_lapsed_at.sql")

	ready, err := store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("expected a database behind this build to report not-ready without an error, got %v", err)
	}
	if ready {
		t.Fatal("expected a database missing an embedded migration to report not-ready")
	}
}

// TestSchemaReadyFailsOnANullRecordedMigrationVersion exercises the scan
// branch of the applied-set read. A TEXT PRIMARY KEY in a SQLite rowid table
// still accepts NULL, so a hand-edited or partially written bookkeeping table
// can hold a row with no version at all — which must fail closed rather than
// be silently skipped and counted as a database that is merely behind.
func TestSchemaReadyFailsOnANullRecordedMigrationVersion(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)

	recordAppliedMigration(t, dbPath, nil)

	ready, err := store.SchemaReady(context.Background())
	if err == nil {
		t.Fatalf("expected SchemaReady to fail on a NULL recorded version, got ready=%v", ready)
	}
	if !strings.Contains(err.Error(), "scan applied migration") {
		t.Fatalf("expected a scan error for the NULL version row, got %v", err)
	}
}

// recordAppliedMigration writes a schema_migrations row through a second
// connection to the same database file — the same technique as dropTable —
// standing in for a newer build having applied a migration this one does not
// embed. version is a test-fixture value chosen by the test (a string, or nil
// for the NULL case), never user input.
func recordAppliedMigration(t *testing.T, dbPath string, version any) {
	t.Helper()

	execOnSecondConnection(
		t,
		dbPath,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`,
		version,
	)
}

// recordAppliedMigrationAt is recordAppliedMigration with a fixed applied_at,
// so a test can assert that value never reaches the refusal message.
func recordAppliedMigrationAt(t *testing.T, dbPath string, version string, appliedAt string) {
	t.Helper()

	execOnSecondConnection(
		t,
		dbPath,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		version,
		appliedAt,
	)
}

// forgetAppliedMigration removes one recorded migration row, leaving the
// database schema itself untouched — the state a binary newer than its
// database is in before `migrate` runs.
func forgetAppliedMigration(t *testing.T, dbPath string, version string) {
	t.Helper()

	execOnSecondConnection(t, dbPath, `DELETE FROM schema_migrations WHERE version = ?`, version)
}

func execOnSecondConnection(t *testing.T, dbPath string, statement string, args ...any) {
	t.Helper()

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer func() {
		_ = raw.Close()
	}()

	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec(statement, args...); err != nil {
		t.Fatalf("exec on second connection: %v", err)
	}
}
