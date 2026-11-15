package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func lateBodyBlob(accountID string) models.EncryptedBlob {
	return models.EncryptedBlob{
		AccountID:      accountID,
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: strings.Repeat("a", 64),
		Ciphertext:     []byte("ciphertext"),
		CiphertextSize: len("ciphertext"),
		UpdatedAt:      time.Now().UTC(),
	}
}

// lateBodyWrites are the session-authenticated writes whose request body can
// arrive after the caller's session was revoked; each must then change nothing.
func lateBodyWrites(store *Store, accountID string) map[string]func(ctx context.Context, tokenHash string) error {
	return map[string]func(ctx context.Context, tokenHash string) error{
		"recovery code rotation": func(ctx context.Context, tokenHash string) error {
			return store.UpdateAccountRecoveryCodeHash(ctx, accountID, tokenHash, "", "verified-hash", "new-recovery-hash")
		},
		"pending totp secret": func(ctx context.Context, tokenHash string) error {
			return store.StorePendingTOTPSecret(ctx, accountID, tokenHash, "pending-secret")
		},
		"device delete": func(ctx context.Context, tokenHash string) error {
			return store.DeleteDevice(ctx, accountID, tokenHash, "device-a")
		},
		"blob upsert": func(ctx context.Context, tokenHash string) error {
			_, err := store.UpsertEncryptedBlob(ctx, tokenHash, lateBodyBlob(accountID))
			return err
		},
	}
}

func seedLateBodyAccount(t *testing.T, store *Store, accountID string) {
	t.Helper()
	ctx := context.Background()
	seedGuardAccount(t, store, accountID)
	if _, err := store.CreateSession(ctx, guardSession(accountID, accountID+"-live")); err != nil {
		t.Fatalf("create session: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.UpsertDevice(ctx, models.Device{
		DeviceID: "device-a", AccountID: accountID, DeviceLabel: "phone", CreatedAt: now, LastSeenAt: now,
	}, 5); err != nil {
		t.Fatalf("create device: %v", err)
	}
}

func TestLateBodyWritesNeedTheCallersSession(t *testing.T) {
	for name := range lateBodyWrites(nil, "") {
		t.Run(name, func(t *testing.T) {
			store := openTestStore(t)
			ctx := context.Background()
			seedLateBodyAccount(t, store, "late-account")
			write := lateBodyWrites(store, "late-account")[name]

			if err := write(ctx, "revoked-session"); !errors.Is(err, ErrSessionRevoked) {
				t.Fatalf("expected ErrSessionRevoked for a session that is gone, got %v", err)
			}
			account, err := store.FindAccountByID(ctx, "late-account")
			if err != nil {
				t.Fatalf("find account: %v", err)
			}
			if account.RecoveryCodeHash != "" || account.TOTPSecretEncrypted != "" {
				t.Fatalf("expected a revoked caller to change nothing, got %#v", account)
			}
			if _, err := store.FindDevice(ctx, "late-account", "device-a"); err != nil {
				t.Fatalf("expected the device kept: %v", err)
			}
			if _, err := store.GetEncryptedBlob(ctx, "late-account"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected no blob written, got %v", err)
			}

			if err := write(ctx, "late-account-live"); err != nil {
				t.Fatalf("expected the live caller's write to go through, got %v", err)
			}
			if err := lateBodyWrites(store, "missing-account")[name](ctx, "late-account-live"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected ErrNotFound for a missing account, got %v", err)
			}
		})
	}
}

func TestEnableTOTPNeedsTheCallersSession(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedLateBodyAccount(t, store, "late-account")
	if err := store.StorePendingTOTPSecret(ctx, "late-account", "late-account-live", "pending-secret"); err != nil {
		t.Fatalf("store pending secret: %v", err)
	}

	err := store.EnableTOTPAndRotateRecoveryCode(ctx, "late-account", "pending-secret", "new-recovery-hash", "revoked-session")
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
	account, err := store.FindAccountByID(ctx, "late-account")
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled || account.RecoveryCodeHash != "" {
		t.Fatalf("expected a revoked caller to enable nothing, got enabled=%v", account.TOTPEnabled)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "late-account-live"); err != nil {
		t.Fatalf("expected the other session kept: %v", err)
	}
}

func TestLateBodyWritesSurfaceStoreFailures(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		ctx := context.Background()
		if err := store.StorePendingTOTPSecret(ctx, "account", "token", "secret"); err == nil || !strings.Contains(err.Error(), "begin store pending totp secret") {
			t.Fatalf("expected the begin error, got %v", err)
		}
		if _, err := store.UpsertEncryptedBlob(ctx, "token", lateBodyBlob("account")); err == nil || !strings.Contains(err.Error(), "begin upsert blob") {
			t.Fatalf("expected the begin error, got %v", err)
		}
	})

	t.Run("sessions table dropped", func(t *testing.T) {
		store, dbPath := newFileBackedTestStore(t)
		seedGuardAccount(t, store, "late-account")
		dropTable(t, dbPath, "sessions")
		err := store.StorePendingTOTPSecret(context.Background(), "late-account", "token", "secret")
		if err == nil || !strings.Contains(err.Error(), "session lookup") {
			t.Fatalf("expected the session lookup error, got %v", err)
		}
	})
}
