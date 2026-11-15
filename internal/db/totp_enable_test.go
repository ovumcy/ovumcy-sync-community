package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func seedPendingResetToken(t *testing.T, store *Store, account models.Account, tokenHash string) {
	t.Helper()

	now := time.Now().UTC()
	if err := store.UpsertPasswordResetToken(context.Background(), models.PasswordResetToken{
		AccountID: account.ID,
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}, account.RecoveryCodeHash); err != nil {
		t.Fatalf("upsert reset token: %v", err)
	}
}

// A reset token issued against the pre-enrollment recovery code dies with the
// enable, and so does every other session of the account; the caller's
// session and a bystander's rows survive. Seeded accounts carry an empty
// pending secret, which is what the caller "verified" here.
func TestEnableTOTPAndRotateRecoveryCodeDeletesResetTokensAndOtherSessions(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")
	bystander := seedFaultInjectionAccount(t, store, "account-bystander")
	seedPendingResetToken(t, store, target, "target-reset-token-hash")
	seedPendingResetToken(t, store, bystander, "bystander-reset-token-hash")
	seedBindingSession(t, store, target.ID, "target-token-current")
	seedBindingSession(t, store, target.ID, "target-token-other")
	seedBindingSession(t, store, bystander.ID, "bystander-token")

	if err := store.EnableTOTPAndRotateRecoveryCode(ctx, target.ID, "", "rotated-recovery-hash", "target-token-current"); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	now := time.Now().UTC()
	if _, err := store.ConsumePasswordResetToken(ctx, "target-reset-token-hash", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the pre-enrollment reset token to be gone, got %v", err)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, "bystander-reset-token-hash", now); err != nil {
		t.Fatalf("expected the bystander's reset token to survive, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "target-token-current"); err != nil {
		t.Fatalf("expected the caller's session to survive, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "target-token-other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the other session to be revoked, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "bystander-token"); err != nil {
		t.Fatalf("expected the bystander's session to survive, got %v", err)
	}
}

// A failed cleanup step rolls the whole enable back: TOTP stays off and the
// old recovery hash stays, so no new code is handed out that never took.
func TestEnableTOTPAndRotateRecoveryCodeRollsBackOnCleanupFailure(t *testing.T) {
	for _, tc := range []struct {
		table   string
		wantErr string
	}{
		{table: "password_reset_tokens", wantErr: "delete reset tokens on totp enable"},
		{table: "sessions", wantErr: "delete other sessions on totp enable"},
	} {
		t.Run(tc.table, func(t *testing.T) {
			store, dbPath := newFileBackedTestStore(t)
			ctx := context.Background()
			target := seedFaultInjectionAccount(t, store, "account-target")
			seedPendingResetToken(t, store, target, "target-reset-token-hash")
			seedBindingSession(t, store, target.ID, "target-token-current")
			seedBindingSession(t, store, target.ID, "target-token-other")

			// The enable first requires the caller's session, so a dropped sessions
			// table would fail the lookup instead of the cleanup delete; a refused
			// delete keeps the table readable and reaches the cleanup branch.
			if tc.table == "sessions" {
				failDeletesOn(t, dbPath, tc.table)
			} else {
				dropTable(t, dbPath, tc.table)
			}

			err := store.EnableTOTPAndRotateRecoveryCode(ctx, target.ID, "", "rotated-recovery-hash", "target-token-current")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected %q to surface, got %v", tc.wantErr, err)
			}

			after, err := store.FindAccountByID(ctx, target.ID)
			if err != nil {
				t.Fatalf("find account: %v", err)
			}
			if after.TOTPEnabled {
				t.Fatal("expected totp_enabled to roll back")
			}
			if after.RecoveryCodeHash != target.RecoveryCodeHash {
				t.Fatalf("expected the recovery hash to roll back, got %q", after.RecoveryCodeHash)
			}
			// The table that was not dropped keeps its row: the earlier
			// delete rolled back with everything else.
			if tc.table == "sessions" {
				if _, err := store.ConsumePasswordResetToken(ctx, "target-reset-token-hash", time.Now().UTC()); err != nil {
					t.Fatalf("expected the reset token to survive the rollback, got %v", err)
				}
			} else if _, err := store.FindSessionByTokenHash(ctx, "target-token-other"); err != nil {
				t.Fatalf("expected the session to survive the rollback, got %v", err)
			}
		})
	}
}

// A start that read "disabled" before a verify committed must not switch the
// enabled factor back off or replace its secret.
func TestStorePendingTOTPSecretRefusesAnEnabledAccount(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")
	seedBindingSession(t, store, target.ID, "target-session")

	if err := store.StorePendingTOTPSecret(ctx, target.ID, target.PasswordHash, "target-session", "pending-secret"); err != nil {
		t.Fatalf("store pending secret: %v", err)
	}
	if err := store.EnableTOTPAndRotateRecoveryCode(ctx, target.ID, "pending-secret", "rotated-recovery-hash", "target-session"); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	if err := store.StorePendingTOTPSecret(ctx, target.ID, target.PasswordHash, "target-session", "late-secret"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict on an enabled account, got %v", err)
	}
	after, err := store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if !after.TOTPEnabled || after.TOTPSecretEncrypted != "pending-secret" {
		t.Fatalf("expected the enabled secret untouched, got enabled=%v secret=%q", after.TOTPEnabled, after.TOTPSecretEncrypted)
	}

	if err := store.StorePendingTOTPSecret(ctx, "missing-account", "hash", "any-session", "secret"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing account, got %v", err)
	}
}

// Discard clears only the pending secret it names, and never an enabled one.
func TestDiscardPendingTOTPSecretOnlyClearsTheNamedPendingSecret(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")
	seedBindingSession(t, store, target.ID, "target-session")

	if err := store.StorePendingTOTPSecret(ctx, target.ID, target.PasswordHash, "target-session", "pending-secret"); err != nil {
		t.Fatalf("store pending secret: %v", err)
	}
	if err := store.DiscardPendingTOTPSecret(ctx, target.ID, "other-secret"); err != nil {
		t.Fatalf("discard other secret: %v", err)
	}
	if after, _ := store.FindAccountByID(ctx, target.ID); after.TOTPSecretEncrypted != "pending-secret" {
		t.Fatalf("expected a mismatched discard to change nothing, got %q", after.TOTPSecretEncrypted)
	}
	if err := store.DiscardPendingTOTPSecret(ctx, target.ID, "pending-secret"); err != nil {
		t.Fatalf("discard pending secret: %v", err)
	}
	if after, _ := store.FindAccountByID(ctx, target.ID); after.TOTPSecretEncrypted != "" {
		t.Fatalf("expected the pending secret cleared, got %q", after.TOTPSecretEncrypted)
	}

	if err := store.StorePendingTOTPSecret(ctx, target.ID, target.PasswordHash, "target-session", "enabled-secret"); err != nil {
		t.Fatalf("store pending secret: %v", err)
	}
	if err := store.EnableTOTPAndRotateRecoveryCode(ctx, target.ID, "enabled-secret", "rotated-recovery-hash", "target-session"); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	if err := store.DiscardPendingTOTPSecret(ctx, target.ID, "enabled-secret"); err != nil {
		t.Fatalf("discard enabled secret: %v", err)
	}
	if after, _ := store.FindAccountByID(ctx, target.ID); !after.TOTPEnabled || after.TOTPSecretEncrypted != "enabled-secret" {
		t.Fatalf("expected an enabled secret to survive a discard, got %#v", after)
	}
}

func TestPendingTOTPSecretWritesFailWhenAccountsTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")
	seedBindingSession(t, store, target.ID, "target-session")

	dropTable(t, dbPath, "accounts")

	if err := store.StorePendingTOTPSecret(ctx, target.ID, target.PasswordHash, "target-session", "secret"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store failure storing a pending secret, got %v", err)
	}
	if err := store.DiscardPendingTOTPSecret(ctx, target.ID, "secret"); err == nil {
		t.Fatal("expected a store failure discarding a pending secret")
	}
}

func TestEnableTOTPAndRotateRecoveryCodeFailsAtBeginTransactionOnClosedStore(t *testing.T) {
	store := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err := store.EnableTOTPAndRotateRecoveryCode(context.Background(), "account-target", "", "any-recovery-hash", "")
	if err == nil || !strings.Contains(err.Error(), "begin enable totp") {
		t.Fatalf("expected the begin-transaction error to surface, got %v", err)
	}
}
