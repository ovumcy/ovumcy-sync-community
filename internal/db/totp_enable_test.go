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

			dropTable(t, dbPath, tc.table)

			err := store.EnableTOTPAndRotateRecoveryCode(ctx, target.ID, "", "rotated-recovery-hash", "")
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
		})
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
