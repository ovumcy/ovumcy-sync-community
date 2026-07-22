package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// corruptTimestampFixture seeds one account with a session, a TOTP challenge,
// a password-reset token, a device, a blob, and a recovery-key package, so
// each scan path has a real row whose timestamp a test can then corrupt
// through an independent raw connection.
type corruptTimestampFixture struct {
	store  *Store
	dbPath string
}

func newCorruptTimestampFixture(t *testing.T) corruptTimestampFixture {
	t.Helper()
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := store.CreateAccount(ctx, models.Account{
		ID:               "corrupt-acct",
		Login:            "corrupt@example.com",
		PasswordHash:     "not-a-real-hash",
		RecoveryCodeHash: "not-a-real-hash",
		Mode:             "community",
		CreatedAt:        now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if _, err := store.CreateSession(ctx, models.Session{
		ID:         "corrupt-session",
		AccountID:  "corrupt-acct",
		TokenHash:  "hash-corrupt-session",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
		ChallengeIDHash: "hash-corrupt-challenge",
		AccountID:       "corrupt-acct",
		CreatedAt:       now,
		ExpiresAt:       now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert challenge: %v", err)
	}
	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: "corrupt-acct",
		TokenHash: "hash-corrupt-reset",
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert reset token: %v", err)
	}
	if _, err := store.UpsertDevice(ctx, models.Device{
		DeviceID:    "corrupt-device",
		AccountID:   "corrupt-acct",
		DeviceLabel: "fixture",
		CreatedAt:   now,
		LastSeenAt:  now,
	}, 5); err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
		AccountID:      "corrupt-acct",
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: strings.Repeat("ab", 32),
		Ciphertext:     []byte("opaque"),
		CiphertextSize: 6,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("upsert blob: %v", err)
	}
	if _, err := store.UpsertRecoveryKeyPackage(ctx, models.RecoveryKeyPackage{
		AccountID:            "corrupt-acct",
		Algorithm:            "xchacha20poly1305",
		KDF:                  "argon2id",
		MnemonicWordCount:    24,
		WrapNonceHex:         strings.Repeat("ab", 24),
		WrappedMasterKeyHex:  strings.Repeat("cd", 48),
		PhraseFingerprintHex: strings.Repeat("ef", 16),
		UpdatedAt:            now,
	}); err != nil {
		t.Fatalf("upsert recovery key package: %v", err)
	}

	return corruptTimestampFixture{store: store, dbPath: dbPath}
}

// corruptColumn rewrites one timestamp column through an independent raw
// connection — simulating the raw database-file write that is the only way a
// stored timestamp can stop parsing, since every repository write path
// formats time.RFC3339Nano. The replacement value deliberately sorts AFTER
// any RFC 3339 string, so rows guarded by lexicographic expiry comparisons
// (expires_at > now) still match and the scan is reached.
func (f corruptTimestampFixture) corruptColumn(t *testing.T, table, column string) {
	t.Helper()
	raw, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`UPDATE ` + table + ` SET ` + column + ` = 'zzz-not-a-timestamp'`); err != nil { // #nosec G202 -- table/column are test-fixture constants chosen by the test table below, never user input
		t.Fatalf("corrupt %s.%s: %v", table, column, err)
	}
}

// TestScansSurfaceCorruptStoredTimestampsAsErrors drives every
// parseStoredTime scan branch through real corruption: after a raw write
// mangles one timestamp column, the corresponding read returns an error
// naming the table and column — the diagnosable-500 contract that replaced
// the old panic.
func TestScansSurfaceCorruptStoredTimestampsAsErrors(t *testing.T) {
	ctx := context.Background()
	for _, testCase := range []struct {
		name    string
		table   string
		column  string
		call    func(*Store) error
		context string
	}{
		{"account created_at", "accounts", "created_at", func(s *Store) error {
			_, err := s.FindAccountByID(ctx, "corrupt-acct")
			return err
		}, "account created_at"},
		{"account lapsed_at", "accounts", "lapsed_at", func(s *Store) error {
			_, err := s.GetAccountLapsedAt(ctx, "corrupt-acct")
			return err
		}, "account lapsed_at"},
		{"session created_at", "sessions", "created_at", func(s *Store) error {
			_, err := s.FindSessionByTokenHash(ctx, "hash-corrupt-session")
			return err
		}, "session created_at"},
		{"session last_seen_at", "sessions", "last_seen_at", func(s *Store) error {
			_, err := s.FindSessionByTokenHash(ctx, "hash-corrupt-session")
			return err
		}, "session last_seen_at"},
		{"session expires_at", "sessions", "expires_at", func(s *Store) error {
			_, err := s.FindSessionByTokenHash(ctx, "hash-corrupt-session")
			return err
		}, "session expires_at"},
		{"totp challenge created_at", "totp_challenges", "created_at", func(s *Store) error {
			_, err := s.FindTOTPChallengeByHash(ctx, "hash-corrupt-challenge")
			return err
		}, "totp challenge created_at"},
		{"totp challenge expires_at", "totp_challenges", "expires_at", func(s *Store) error {
			_, err := s.FindTOTPChallengeByHash(ctx, "hash-corrupt-challenge")
			return err
		}, "totp challenge expires_at"},
		{"password reset token created_at", "password_reset_tokens", "created_at", func(s *Store) error {
			_, err := s.ConsumePasswordResetToken(ctx, "hash-corrupt-reset", time.Now().UTC())
			return err
		}, "password reset token created_at"},
		{"password reset token expires_at", "password_reset_tokens", "expires_at", func(s *Store) error {
			// The corrupt value sorts after the formatted now, so the
			// consume CAS still matches the row and the scan is reached.
			_, err := s.ConsumePasswordResetToken(ctx, "hash-corrupt-reset", time.Now().UTC())
			return err
		}, "password reset token expires_at"},
		{"device created_at", "devices", "created_at", func(s *Store) error {
			_, err := s.FindDevice(ctx, "corrupt-acct", "corrupt-device")
			return err
		}, "device created_at"},
		{"device last_seen_at", "devices", "last_seen_at", func(s *Store) error {
			_, err := s.FindDevice(ctx, "corrupt-acct", "corrupt-device")
			return err
		}, "device last_seen_at"},
		{"blob updated_at", "encrypted_blobs", "updated_at", func(s *Store) error {
			_, err := s.GetEncryptedBlob(ctx, "corrupt-acct")
			return err
		}, "blob updated_at"},
		{"recovery key package updated_at", "recovery_key_packages", "updated_at", func(s *Store) error {
			_, err := s.GetRecoveryKeyPackage(ctx, "corrupt-acct")
			return err
		}, "recovery key package updated_at"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newCorruptTimestampFixture(t)
			fixture.corruptColumn(t, testCase.table, testCase.column)

			err := testCase.call(fixture.store)
			if err == nil {
				t.Fatalf("expected a corrupt %s.%s to surface as an error", testCase.table, testCase.column)
			}
			if !strings.Contains(err.Error(), "parse stored timestamp") {
				t.Fatalf("expected a parse-stored-timestamp error, got %v", err)
			}
			if !strings.Contains(err.Error(), testCase.context) {
				t.Fatalf("expected the error to carry the %q context, got %v", testCase.context, err)
			}
		})
	}
}

// TestIsUniqueConstraintFallsBackToTheDriverMessage pins the fallback branch:
// an error that is not the driver's typed *sqlite.Error is still recognized
// by SQLite's own stable message, and everything else stays false.
func TestIsUniqueConstraintFallsBackToTheDriverMessage(t *testing.T) {
	if !isUniqueConstraint(errors.New("UNIQUE constraint failed: accounts.login")) {
		t.Fatal("expected the message fallback to recognize a re-wrapped unique violation")
	}
	if isUniqueConstraint(errors.New("some other failure")) {
		t.Fatal("expected an unrelated error to stay non-unique")
	}
	if isUniqueConstraint(nil) {
		t.Fatal("expected nil to stay non-unique")
	}
}
