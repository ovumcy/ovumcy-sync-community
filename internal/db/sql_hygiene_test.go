package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// TestExpiredRowsSweepRemovesAnUnreadableExpiry pins that a row whose
// expires_at julianday() cannot read (NULL) is swept: every lookup already
// treats it as expired, so without the IS NULL arm it would stay forever.
func TestExpiredRowsSweepRemovesAnUnreadableExpiry(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "corrupt")
	future := time.Now().UTC().Add(time.Hour)

	createSessionExpiringAt(t, store, account.ID, "corrupt-session", future)
	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: account.ID,
		TokenHash: "corrupt-token",
		CreatedAt: future.Add(-2 * time.Hour),
		ExpiresAt: future,
	}, account.RecoveryCodeHash); err != nil {
		t.Fatalf("upsert reset token: %v", err)
	}
	if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
		ChallengeIDHash: "corrupt-challenge",
		AccountID:       account.ID,
		CreatedAt:       future.Add(-2 * time.Hour),
		ExpiresAt:       future,
	}); err != nil {
		t.Fatalf("upsert totp challenge: %v", err)
	}
	for _, table := range []string{"sessions", "password_reset_tokens", "totp_challenges"} {
		if _, err := store.db.ExecContext(ctx, `UPDATE `+table+` SET expires_at = 'not-a-time' WHERE account_id = ?`, account.ID); err != nil { // #nosec G202 -- fixed test table names
			t.Fatalf("corrupt %s: %v", table, err)
		}
	}

	cutoff := time.Now().UTC()
	for name, sweep := range map[string]func(context.Context, time.Time, int) (int64, error){
		"sessions":              store.DeleteExpiredSessions,
		"password_reset_tokens": store.DeleteExpiredPasswordResetTokens,
		"totp_challenges":       store.DeleteExpiredTOTPChallenges,
	} {
		deleted, err := sweep(ctx, cutoff, 0)
		if err != nil {
			t.Fatalf("%s sweep: %v", name, err)
		}
		if deleted != 1 {
			t.Fatalf("%s: expected the unreadable row swept, got %d", name, deleted)
		}
	}
}

// TestDeleteManagedAccountLeavesASelfHostedAccountIntact pins the bridge
// purge's SQL guard: a non-managed account is refused with ErrNotFound and
// keeps every row, including the child rows deleted before the guard.
func TestDeleteManagedAccountLeavesASelfHostedAccountIntact(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "self-hosted")
	createSessionExpiringAt(t, store, account.ID, "self-hosted-session", time.Now().UTC().Add(time.Hour))

	if err := store.DeleteManagedAccount(ctx, account.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a self-hosted account, got %v", err)
	}
	if _, err := store.FindAccountByID(ctx, account.ID); err != nil {
		t.Fatalf("account must survive: %v", err)
	}
	var sessions int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE account_id = ?`, account.ID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 1 {
		t.Fatalf("expected the session rolled back into place, got %d rows", sessions)
	}

	managed, err := store.CreateAccount(ctx, models.Account{
		ID:               "managed-purge-target",
		Login:            "managed-purge-target",
		PasswordHash:     "not-a-real-hash",
		RecoveryCodeHash: "not-a-real-hash",
		Mode:             "managed",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	if err := store.DeleteManagedAccount(ctx, managed.ID); err != nil {
		t.Fatalf("delete managed account: %v", err)
	}
	if _, err := store.FindAccountByID(ctx, managed.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the managed account gone, got %v", err)
	}
}

// TestUpsertEncryptedBlobStoresCreatedAtInTheWriteFormat pins that a new
// blob's created_at is RFC3339Nano like every other write, not SQLite's
// CURRENT_TIMESTAMP text.
func TestUpsertEncryptedBlobStoresCreatedAtInTheWriteFormat(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "blob-owner")
	createSessionExpiringAt(t, store, account.ID, "blob-session", time.Now().UTC().Add(time.Hour))

	updatedAt := time.Date(2026, 11, 17, 10, 0, 0, 123456789, time.UTC)
	if _, err := store.UpsertEncryptedBlob(ctx, "hash-blob-session", models.EncryptedBlob{
		AccountID:      account.ID,
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: "00",
		Ciphertext:     []byte("ciphertext"),
		CiphertextSize: len("ciphertext"),
		UpdatedAt:      updatedAt,
	}); err != nil {
		t.Fatalf("upsert blob: %v", err)
	}

	var createdAt string
	if err := store.db.QueryRowContext(ctx, `SELECT created_at FROM encrypted_blobs WHERE account_id = ?`, account.ID).Scan(&createdAt); err != nil {
		t.Fatalf("read created_at: %v", err)
	}
	if createdAt != updatedAt.Format(time.RFC3339Nano) {
		t.Fatalf("expected created_at %q, got %q", updatedAt.Format(time.RFC3339Nano), createdAt)
	}
}
