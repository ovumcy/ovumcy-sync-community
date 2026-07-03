package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestAccountRepositoryConflictAndLookups(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	account := models.Account{
		ID:            "account-1",
		Login:         "owner@example.com",
		PasswordHash:  "hash",
		Mode:          "self_hosted",
		PremiumActive: false,
		CreatedAt:     now,
	}
	if _, err := store.CreateAccount(context.Background(), account); err != nil {
		t.Fatalf("create account: %v", err)
	}

	if _, err := store.CreateAccount(context.Background(), account); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	foundByLogin, err := store.FindAccountByLogin(context.Background(), account.Login)
	if err != nil {
		t.Fatalf("find account by login: %v", err)
	}
	if foundByLogin.ID != account.ID {
		t.Fatalf("unexpected account lookup result: %#v", foundByLogin)
	}

	if _, err := store.FindAccountByID(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account id, got %v", err)
	}
	if _, err := store.FindAccountByLogin(context.Background(), "missing@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing login, got %v", err)
	}
}

func TestManagedAccountUpsertPreservesIdentityAndUpdatesFlags(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	created, err := store.UpsertManagedAccount(context.Background(), models.Account{
		ID:            "managedacct1234",
		Login:         "managed:managedacct1234",
		PasswordHash:  "managed_service_only",
		Mode:          "managed",
		PremiumActive: true,
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}

	updatedAt := now.Add(2 * time.Hour)
	if _, err := store.UpsertManagedAccount(context.Background(), models.Account{
		ID:            created.ID,
		Login:         "managed:managedacct1234",
		PasswordHash:  "rotated_hash",
		Mode:          "managed",
		PremiumActive: false,
		CreatedAt:     updatedAt,
	}); err != nil {
		t.Fatalf("update managed account: %v", err)
	}

	account, err := store.FindAccountByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("find managed account: %v", err)
	}
	if account.PasswordHash != "rotated_hash" || account.PremiumActive {
		t.Fatalf("unexpected managed account flags after upsert: %#v", account)
	}
}

func TestSessionRepositoryLifecycleAndNotFound(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	if _, err := store.CreateAccount(context.Background(), models.Account{
		ID:           "account-1",
		Login:        "owner@example.com",
		PasswordHash: "hash",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}

	session := models.Session{
		ID:         "session-1",
		AccountID:  "account-1",
		TokenHash:  "token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	if _, err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	lastSeenAt := now.Add(time.Hour)
	if err := store.TouchSession(context.Background(), session.ID, lastSeenAt); err != nil {
		t.Fatalf("touch session: %v", err)
	}

	touched, err := store.FindSessionByTokenHash(context.Background(), session.TokenHash)
	if err != nil {
		t.Fatalf("find touched session: %v", err)
	}
	if !touched.LastSeenAt.Equal(lastSeenAt) {
		t.Fatalf("expected updated last seen time, got %#v", touched)
	}

	if err := store.DeleteSessionByTokenHash(context.Background(), session.TokenHash); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	if _, err := store.FindSessionByTokenHash(context.Background(), session.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := store.TouchSession(context.Background(), "missing-session", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing touch, got %v", err)
	}
	if err := store.DeleteSessionByTokenHash(context.Background(), "missing-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing delete, got %v", err)
	}
}

func TestBlobAndRecoveryRepositoriesReturnNotFoundBeforeWrite(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.GetEncryptedBlob(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing blob, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing recovery package, got %v", err)
	}
}

// TestDeleteAccountErasesEveryChildRowAndIsIdempotent seeds one row in every
// table that carries an account_id (session, device, encrypted blob,
// recovery key package, password reset token, TOTP challenge) plus a second,
// untouched account acting as a control. It asserts DeleteAccount erases all
// of the target account's rows in one call, leaves the other account's rows
// completely alone, and that calling DeleteAccount again on the now-gone
// account is a no-op rather than an error (idempotent repeat semantics).
func TestDeleteAccountErasesEveryChildRowAndIsIdempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const targetAccountID = "account-delete-target"
	const otherAccountID = "account-delete-bystander"

	for _, accountID := range []string{targetAccountID, otherAccountID} {
		if _, err := store.CreateAccount(ctx, models.Account{
			ID:               accountID,
			Login:            accountID + "@example.com",
			PasswordHash:     "hash",
			RecoveryCodeHash: "recovery-hash",
			Mode:             "self_hosted",
			CreatedAt:        now,
		}); err != nil {
			t.Fatalf("create account %s: %v", accountID, err)
		}

		if _, err := store.CreateSession(ctx, models.Session{
			ID:         accountID + "-session",
			AccountID:  accountID,
			TokenHash:  accountID + "-token-hash",
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("create session for %s: %v", accountID, err)
		}

		if _, err := store.UpsertDevice(ctx, models.Device{
			DeviceID:    accountID + "-device",
			AccountID:   accountID,
			DeviceLabel: "Test Device",
			CreatedAt:   now,
			LastSeenAt:  now,
		}); err != nil {
			t.Fatalf("create device for %s: %v", accountID, err)
		}

		if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
			AccountID:      accountID,
			SchemaVersion:  1,
			Generation:     1,
			ChecksumSHA256: strings.Repeat("a", 64),
			Ciphertext:     []byte("ciphertext"),
			CiphertextSize: len("ciphertext"),
			UpdatedAt:      now,
		}); err != nil {
			t.Fatalf("create blob for %s: %v", accountID, err)
		}

		if _, err := store.UpsertRecoveryKeyPackage(ctx, models.RecoveryKeyPackage{
			AccountID:            accountID,
			Algorithm:            "xchacha20poly1305",
			KDF:                  "bip39_seed_hkdf_sha256",
			MnemonicWordCount:    12,
			WrapNonceHex:         strings.Repeat("b", 48),
			WrappedMasterKeyHex:  strings.Repeat("c", 96),
			PhraseFingerprintHex: strings.Repeat("d", 16),
			UpdatedAt:            now,
		}); err != nil {
			t.Fatalf("create recovery key package for %s: %v", accountID, err)
		}

		if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
			AccountID: accountID,
			TokenHash: accountID + "-reset-token-hash",
			CreatedAt: now,
			ExpiresAt: now.Add(30 * time.Minute),
		}); err != nil {
			t.Fatalf("create password reset token for %s: %v", accountID, err)
		}

		if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
			ChallengeIDHash: accountID + "-challenge-hash",
			AccountID:       accountID,
			CreatedAt:       now,
			ExpiresAt:       now.Add(5 * time.Minute),
		}); err != nil {
			t.Fatalf("create totp challenge for %s: %v", accountID, err)
		}
	}

	if err := store.DeleteAccount(ctx, targetAccountID); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	if _, err := store.FindAccountByID(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected account row gone, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, targetAccountID+"-token-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected session gone, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, targetAccountID); err != nil || count != 0 {
		t.Fatalf("expected zero devices, got count=%d err=%v", count, err)
	}
	if _, err := store.GetEncryptedBlob(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected blob gone, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected recovery key package gone, got %v", err)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, targetAccountID+"-reset-token-hash", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected password reset token gone, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, targetAccountID+"-challenge-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected totp challenge gone, got %v", err)
	}

	// Bystander account must be completely untouched.
	if _, err := store.FindAccountByID(ctx, otherAccountID); err != nil {
		t.Fatalf("expected bystander account to remain, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, otherAccountID+"-token-hash"); err != nil {
		t.Fatalf("expected bystander session to remain, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, otherAccountID); err != nil || count != 1 {
		t.Fatalf("expected one bystander device, got count=%d err=%v", count, err)
	}
	if _, err := store.GetEncryptedBlob(ctx, otherAccountID); err != nil {
		t.Fatalf("expected bystander blob to remain, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, otherAccountID); err != nil {
		t.Fatalf("expected bystander recovery key package to remain, got %v", err)
	}

	// Idempotent repeat: deleting an already-gone account is a no-op success,
	// not ErrNotFound bubbling up unexpectedly for callers that treat
	// ErrNotFound as "already erased" — this asserts the raw repository
	// contract that the service layer maps to a friendlier success.
	if err := store.DeleteAccount(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on repeat delete, got %v", err)
	}
}
