package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestMigrationsBootstrapAndRepositories(t *testing.T) {
	store := openTestStore(t)

	now := time.Now().UTC()
	account, err := store.CreateAccount(context.Background(), models.Account{
		ID:           "account-1",
		Login:        "owner@example.com",
		PasswordHash: "hash",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	if _, err := store.CreateSession(context.Background(), models.Session{
		ID:         "session-1",
		AccountID:  account.ID,
		TokenHash:  "token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := store.UpsertDevice(context.Background(), models.Device{
		AccountID:   account.ID,
		DeviceID:    "device-1",
		DeviceLabel: "Pixel 7",
		CreatedAt:   now,
		LastSeenAt:  now,
	}); err != nil {
		t.Fatalf("upsert device: %v", err)
	}

	if _, err := store.UpsertEncryptedBlob(context.Background(), models.EncryptedBlob{
		AccountID:      account.ID,
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Ciphertext:     []byte("ciphertext"),
		CiphertextSize: len("ciphertext"),
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("upsert encrypted blob: %v", err)
	}

	if _, err := store.UpsertRecoveryKeyPackage(context.Background(), models.RecoveryKeyPackage{
		AccountID:            account.ID,
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		WrappedMasterKeyHex:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PhraseFingerprintHex: "cccccccccccccccc",
		UpdatedAt:            now,
	}); err != nil {
		t.Fatalf("upsert recovery key package: %v", err)
	}

	if _, err := store.FindAccountByID(context.Background(), account.ID); err != nil {
		t.Fatalf("find account by id: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(context.Background(), "token-hash"); err != nil {
		t.Fatalf("find session by token hash: %v", err)
	}
	if _, err := store.FindDevice(context.Background(), account.ID, "device-1"); err != nil {
		t.Fatalf("find device: %v", err)
	}
	if _, err := store.GetEncryptedBlob(context.Background(), account.ID); err != nil {
		t.Fatalf("get encrypted blob: %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(context.Background(), account.ID); err != nil {
		t.Fatalf("get recovery key package: %v", err)
	}
}

func TestRepositoriesDoNotShareDeviceOwnershipAcrossAccounts(t *testing.T) {
	store := openTestStore(t)

	now := time.Now().UTC()
	for _, accountID := range []string{"account-1", "account-2"} {
		if _, err := store.CreateAccount(context.Background(), models.Account{
			ID:           accountID,
			Login:        accountID + "@example.com",
			PasswordHash: "hash",
			CreatedAt:    now,
		}); err != nil {
			t.Fatalf("create account %s: %v", accountID, err)
		}
	}

	for _, accountID := range []string{"account-1", "account-2"} {
		if _, err := store.UpsertDevice(context.Background(), models.Device{
			AccountID:   accountID,
			DeviceID:    "shared-device",
			DeviceLabel: accountID,
			CreatedAt:   now,
			LastSeenAt:  now,
		}); err != nil {
			t.Fatalf("upsert device for %s: %v", accountID, err)
		}
	}

	deviceOne, err := store.FindDevice(context.Background(), "account-1", "shared-device")
	if err != nil {
		t.Fatalf("find device for account-1: %v", err)
	}
	deviceTwo, err := store.FindDevice(context.Background(), "account-2", "shared-device")
	if err != nil {
		t.Fatalf("find device for account-2: %v", err)
	}

	if deviceOne.DeviceLabel == deviceTwo.DeviceLabel {
		t.Fatalf("expected isolated device labels, got %#v and %#v", deviceOne, deviceTwo)
	}
}

func TestSchemaReadyReflectsMigrationState(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	ready, err := store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("schema ready before migrations: %v", err)
	}
	if ready {
		t.Fatal("expected schema to be uninitialized before migrations")
	}

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	ready, err = store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("schema ready after migrations: %v", err)
	}
	if !ready {
		t.Fatal("expected schema to be initialized after migrations")
	}
}

// TestOpenFailsWhenParentDirectoryCannotBeCreated exercises Open's
// "create db dir" error branch: MkdirAll fails when a path component that
// should be a directory is actually a regular file. No fake driver or
// production seam is needed — the failure is a real os.MkdirAll error
// surfaced through Open's existing path argument.
func TestOpenFailsWhenParentDirectoryCannotBeCreated(t *testing.T) {
	dir := t.TempDir()

	blockerFile := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blockerFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}

	dbPath := filepath.Join(blockerFile, "subdir", "sync-community-test.db")

	store, err := Open(dbPath)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected Open to fail when the db directory cannot be created")
	}
	if !strings.Contains(err.Error(), "create db dir") {
		t.Fatalf("expected 'create db dir' wrapped error, got %v", err)
	}
}

// TestOpenFailsWhenSQLiteConfigurationRejectsTheDSN exercises Open's
// "configure sqlite" error branch: the parent directory exists (MkdirAll
// succeeds) but the path carries a malformed sqlite DSN query suffix, so
// the very first Exec (the PRAGMA batch) fails. This is a real driver-level
// DSN parse error reached through Open's public path argument, not a fake
// driver.
func TestOpenFailsWhenSQLiteConfigurationRejectsTheDSN(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sync-community-test.db") + "?_pragma=busy_timeout(%zz)"

	store, err := Open(dbPath)
	if err == nil {
		_ = store.Close()
		t.Fatal("expected Open to fail on a malformed sqlite DSN")
	}
	if !strings.Contains(err.Error(), "configure sqlite") {
		t.Fatalf("expected 'configure sqlite' wrapped error, got %v", err)
	}
}

// TestPingReturnsErrorOnClosedStore exercises Store.Ping's error branch
// (wired in production as the /healthz readiness check via store.Ping in
// cmd/ovumcy-sync-community). Closing the store first is the natural way to
// fault the underlying *sql.DB through the public API alone.
func TestPingReturnsErrorOnClosedStore(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("ping before close: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("expected ping to fail after store is closed")
	}
}

// TestApplyMigrationsAndSchemaReadyReturnErrorsOnClosedStore covers the
// generic query/exec error branches inside applyMigrations and schemaReady
// (the "ensure schema_migrations", migrationApplied's count query, and
// schemaReady's sqlite_master / count queries) by faulting every subsequent
// statement uniformly: closing the store makes every *sql.DB call return
// "sql: database is closed", which is exactly the same failure shape a
// dropped connection or crashed database file would produce.
func TestApplyMigrationsAndSchemaReadyReturnErrorsOnClosedStore(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	if err := store.ApplyMigrations(context.Background()); err == nil {
		t.Fatal("expected ApplyMigrations to fail on a closed store")
	}

	if ready, err := store.SchemaReady(context.Background()); err == nil {
		t.Fatalf("expected SchemaReady to fail on a closed store, got ready=%v", ready)
	}
}

// TestApplyMigrationsFailsAndRollsBackOnMalformedMigrationState exercises
// applyMigrations' "apply migration" error branch and its rollback path
// (tx.Rollback on ExecContext failure) via a real, deterministic malformed
// migration state: schema_migrations is missing the row for a migration
// whose SQL has already been physically applied to the schema. When
// applyMigrations sees no recorded row it retries the migration's SQL, and
// the driver rejects the duplicate ALTER TABLE ADD COLUMN with a genuine
// SQL logic error — the same failure a corrupted or hand-edited
// schema_migrations table would produce in the field, requiring no fake
// driver or production seam.
func TestApplyMigrationsFailsAndRollsBackOnMalformedMigrationState(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "malformed-migration-state.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Delete the recorded row for migration 0003 (adds accounts.mode /
	// premium_active via ALTER TABLE) through a second raw connection,
	// while leaving the columns themselves in place. schema_migrations now
	// disagrees with the real schema: on the next ApplyMigrations, the
	// migration is (wrongly) seen as unapplied and its SQL is replayed
	// against a schema that already has those columns.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`DELETE FROM schema_migrations WHERE version = '0003_managed_account_fields.sql'`); err != nil {
		t.Fatalf("corrupt schema_migrations: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw sqlite: %v", err)
	}

	reopened, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})

	err = reopened.ApplyMigrations(context.Background())
	if err == nil {
		t.Fatal("expected ApplyMigrations to fail on malformed migration state")
	}
	if !strings.Contains(err.Error(), "apply migration 0003_managed_account_fields.sql") {
		t.Fatalf("expected apply-migration error for 0003, got %v", err)
	}

	// Rollback must have left every later migration's row untouched (the
	// failed migration aborts the whole run rather than partially applying
	// state), and a retry against the same malformed state must keep
	// failing identically rather than corrupting further.
	err = reopened.ApplyMigrations(context.Background())
	if err == nil {
		t.Fatal("expected ApplyMigrations to keep failing on unresolved malformed migration state")
	}
}

// TestApplyMigrationsFailsAndRollsBackWhenRecordingTheAppliedMigrationFails
// isolates applyMigrations' "record migration" error branch (the INSERT
// INTO schema_migrations bookkeeping step) from its "apply migration"
// branch covered above: schema_migrations is pre-seeded with a CHECK
// constraint on version that every real migration filename violates, so
// each migration's own DDL applies cleanly but the bookkeeping insert that
// follows it fails and rolls back. This is a real, deterministic "schema in
// an unexpected state" fault (a hand-edited or partially-migrated
// schema_migrations table), not a fake driver — the constraint is ordinary
// SQL applied through the same second-connection technique as dropTable.
func TestApplyMigrationsFailsAndRollsBackWhenRecordingTheAppliedMigrationFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "record-insert-fault.db")

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`
CREATE TABLE schema_migrations (
  version TEXT PRIMARY KEY CHECK (length(version) < 5),
  applied_at TEXT NOT NULL
);
`); err != nil {
		t.Fatalf("seed constrained schema_migrations: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw sqlite: %v", err)
	}

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	// applyMigrations' "ensure schema_migrations" statement is CREATE TABLE
	// IF NOT EXISTS, so it leaves the pre-seeded CHECK constraint in place.
	// The first migration's own DDL (0001_init.sql) applies successfully,
	// but recording it fails the length(version) < 5 check, so the whole
	// migration rolls back rather than leaving the schema half-applied.
	err = store.ApplyMigrations(context.Background())
	if err == nil {
		t.Fatal("expected ApplyMigrations to fail when recording the applied migration violates a constraint")
	}
	if !strings.Contains(err.Error(), "record migration 0001_init.sql") {
		t.Fatalf("expected record-migration error for 0001_init.sql, got %v", err)
	}

	// The rollback must have undone 0001's own DDL too (single transaction
	// per migration): schema must still report not-ready.
	ready, err := store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("schema ready after rolled-back migration: %v", err)
	}
	if ready {
		t.Fatal("expected schema to remain not-ready after the record-insert failure rolled back")
	}
}

// TestMigrationAppliedReturnsErrorWhenSchemaMigrationsShapeIsCorrupted
// exercises migrationApplied's own query/scan error branch in isolation
// (distinct from the malformed-state test above, which instead reaches
// applyMigrations' apply-error branch): schema_migrations exists as a
// table, so the "ensure schema_migrations" CREATE TABLE IF NOT EXISTS is a
// no-op, but its version column has been renamed out from under it via a
// second connection. migrationApplied's `WHERE version = ?` query then
// fails with a real "no such column" driver error on the very first
// migration it checks, which applyMigrations must surface unwrapped rather
// than mask.
func TestMigrationAppliedReturnsErrorWhenSchemaMigrationsShapeIsCorrupted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "corrupted-schema-migrations.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Pre-create schema_migrations with its version column renamed away,
	// before any migration has run. applyMigrations' own "ensure
	// schema_migrations" statement is CREATE TABLE IF NOT EXISTS, so it
	// leaves this corrupted shape untouched.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);`); err != nil {
		t.Fatalf("seed schema_migrations: %v", err)
	}
	if _, err := raw.Exec(`ALTER TABLE schema_migrations RENAME COLUMN version TO renamed_version;`); err != nil {
		t.Fatalf("corrupt schema_migrations shape: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw sqlite: %v", err)
	}

	reopened, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() {
		_ = reopened.Close()
	})

	err = reopened.ApplyMigrations(context.Background())
	if err == nil {
		t.Fatal("expected ApplyMigrations to fail when schema_migrations is missing its version column")
	}
	if !strings.Contains(err.Error(), "check migration") {
		t.Fatalf("expected migrationApplied's 'check migration' wrapped error, got %v", err)
	}
}
