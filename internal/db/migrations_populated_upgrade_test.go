package db

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// TestMigratingAPopulatedFirstReleaseDatabaseKeepsEveryRow seeds the 0001
// schema with rows shaped as the first release wrote them (the blob's
// created_at as SQLite CURRENT_TIMESTAMP text), steps to 0005 to seed the
// tables 0002-0005 create, applies every later migration over the populated
// tables, and reads and writes them back through the Store.
func TestMigratingAPopulatedFirstReleaseDatabaseKeepsEveryRow(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "first-release.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	initSQL, err := migrationFiles.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("read 0001: %v", err)
	}
	created := time.Date(2025, 6, 1, 9, 30, 0, 250_000_000, time.UTC)
	stamp := created.Format(time.RFC3339Nano)
	expires := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	ciphertext := []byte("first-release-ciphertext")
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`, nil},
		{string(initSQL), nil},
		{`INSERT INTO schema_migrations (version, applied_at) VALUES ('0001_init.sql', CURRENT_TIMESTAMP)`, nil},
		{`INSERT INTO accounts (id, login, password_hash, created_at) VALUES (?, ?, ?, ?)`,
			[]any{"v1-account", "v1@example.com", "v1-password-hash", stamp}},
		{`INSERT INTO sessions (id, account_id, token_hash, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			[]any{"v1-session", "v1-account", "v1-token-hash", stamp, stamp, expires.Format(time.RFC3339Nano)}},
		{`INSERT INTO devices (account_id, device_id, device_label, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)`,
			[]any{"v1-account", "v1-device", "Pixel 7", stamp, stamp}},
		{`INSERT INTO encrypted_blobs (account_id, schema_version, generation, checksum_sha256, ciphertext, ciphertext_size, created_at, updated_at) VALUES (?, 1, 3, ?, ?, ?, CURRENT_TIMESTAMP, ?)`,
			[]any{"v1-account", "aa", ciphertext, len(ciphertext), stamp}},
	} {
		if _, err := store.db.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed first-release database: %v", err)
		}
	}

	// Stop at 0005 and seed the tables whose rows a later ALTER must carry:
	// 0006 adds totp_challenges.failed_attempts, 0007 adds
	// password_reset_tokens.consumed_at.
	for _, version := range []string{
		"0002_recovery_key_packages.sql",
		"0003_managed_account_fields.sql",
		"0004_recovery_codes_and_reset_tokens.sql",
		"0005_totp.sql",
	} {
		body, err := migrationFiles.ReadFile("migrations/" + version)
		if err != nil {
			t.Fatalf("read %s: %v", version, err)
		}
		if _, err := store.db.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", version, err)
		}
		if _, err := store.db.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`, version); err != nil {
			t.Fatalf("record %s: %v", version, err)
		}
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO recovery_key_packages (account_id, algorithm, kdf, mnemonic_word_count, wrap_nonce_hex, wrapped_master_key_hex, phrase_fingerprint_hex, updated_at) VALUES (?, 'v5-algorithm', 'v5-kdf', 24, 'aa', 'bb', 'cc', ?)`,
			[]any{"v1-account", stamp}},
		{`INSERT INTO password_reset_tokens (account_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
			[]any{"v1-account", "v5-reset-hash", stamp, expires.Format(time.RFC3339Nano)}},
		{`INSERT INTO totp_challenges (challenge_id_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
			[]any{"v5-challenge-hash", "v1-account", stamp, expires.Format(time.RFC3339Nano)}},
	} {
		if _, err := store.db.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed 0005 database: %v", err)
		}
	}

	if ready, err := store.SchemaReady(ctx); err != nil || ready {
		t.Fatalf("expected a first-release database to be pending, got ready=%v err=%v", ready, err)
	}
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("migrate populated database: %v", err)
	}
	if ready, err := store.SchemaReady(ctx); err != nil || !ready {
		t.Fatalf("expected the migrated database ready, got ready=%v err=%v", ready, err)
	}

	account, err := store.FindAccountByID(ctx, "v1-account")
	if err != nil {
		t.Fatalf("find migrated account: %v", err)
	}
	if account.Login != "v1@example.com" || account.PasswordHash != "v1-password-hash" ||
		account.Mode != "self_hosted" || account.TOTPEnabled || account.RecoveryCodeHash != "" ||
		!account.CreatedAt.Equal(created) {
		t.Fatalf("migrated account changed: %#v", account)
	}

	session, err := store.FindSessionByTokenHash(ctx, "v1-token-hash")
	if err != nil {
		t.Fatalf("find migrated session: %v", err)
	}
	if session.AccountID != "v1-account" || !session.ExpiresAt.Equal(expires) {
		t.Fatalf("migrated session changed: %#v", session)
	}

	device, err := store.FindDevice(ctx, "v1-account", "v1-device")
	if err != nil {
		t.Fatalf("find migrated device: %v", err)
	}
	if device.DeviceLabel != "Pixel 7" || !device.CreatedAt.Equal(created) {
		t.Fatalf("migrated device changed: %#v", device)
	}

	blob, err := store.GetEncryptedBlob(ctx, "v1-account")
	if err != nil {
		t.Fatalf("get migrated blob: %v", err)
	}
	if blob.Generation != 3 || !bytes.Equal(blob.Ciphertext, ciphertext) || !blob.UpdatedAt.Equal(created) {
		t.Fatalf("migrated blob changed: %#v", blob)
	}

	recoveryPackage, err := store.GetRecoveryKeyPackage(ctx, "v1-account")
	if err != nil {
		t.Fatalf("get migrated recovery key package: %v", err)
	}
	if recoveryPackage.Algorithm != "v5-algorithm" || recoveryPackage.MnemonicWordCount != 24 ||
		!recoveryPackage.UpdatedAt.Equal(created) {
		t.Fatalf("migrated recovery key package changed: %#v", recoveryPackage)
	}

	if attempts, err := store.IncrementTOTPChallengeFailedAttempts(ctx, "v5-challenge-hash"); err != nil || attempts != 1 {
		t.Fatalf("expected the migrated challenge's first failure counted as 1, got %d, %v", attempts, err)
	}

	resetToken, err := store.ConsumePasswordResetToken(ctx, "v5-reset-hash", created.Add(time.Hour))
	if err != nil {
		t.Fatalf("consume migrated reset token: %v", err)
	}
	if resetToken.AccountID != "v1-account" || !resetToken.ExpiresAt.Equal(expires) {
		t.Fatalf("migrated reset token changed: %#v", resetToken)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, "v5-reset-hash", created.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the migrated reset token single-use, got %v", err)
	}

	next := []byte("after-upgrade")
	if _, err := store.UpsertEncryptedBlob(ctx, "v1-token-hash", noGenerationCeiling, models.EncryptedBlob{
		AccountID:      "v1-account",
		SchemaVersion:  1,
		Generation:     4,
		ChecksumSHA256: "bb",
		Ciphertext:     next,
		CiphertextSize: len(next),
		UpdatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("write blob after upgrade: %v", err)
	}

	if err := store.DeleteAccountForSession(ctx, "v1-account", "v1-password-hash", false, "v1-token-hash"); err != nil {
		t.Fatalf("delete migrated account: %v", err)
	}
	if _, err := store.FindAccountByID(ctx, "v1-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the migrated account erased, got %v", err)
	}
	for _, table := range []string{"sessions", "devices", "encrypted_blobs", "recovery_key_packages", "password_reset_tokens", "totp_challenges"} {
		var rows int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&rows); err != nil { // #nosec G202 -- fixed test table names
			t.Fatalf("count %s: %v", table, err)
		}
		if rows != 0 {
			t.Fatalf("expected %s erased with the account, got %d rows", table, rows)
		}
	}
}
