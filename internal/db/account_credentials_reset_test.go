package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// seedResetAccount creates an account with TOTP enabled and a claimed step,
// one session, one pending TOTP challenge, and one reset token whose hash is
// accountID+"-token".
func seedResetAccount(t *testing.T, store *Store, accountID string, tokenExpiresAt time.Time) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := store.CreateAccount(ctx, models.Account{
		ID:               accountID,
		Login:            accountID + "@example.com",
		PasswordHash:     "old-password-hash",
		RecoveryCodeHash: "old-recovery-hash",
		Mode:             "self_hosted",
		CreatedAt:        now,
	}); err != nil {
		t.Fatalf("seed account %s: %v", accountID, err)
	}
	if err := store.UpdateTOTPSecretAndEnabled(ctx, accountID, "sealed-secret", true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	if _, err := store.ClaimTOTPStep(ctx, accountID, 42); err != nil {
		t.Fatalf("claim totp step: %v", err)
	}
	if _, err := store.CreateSession(ctx, models.Session{
		ID:         accountID + "-session",
		AccountID:  accountID,
		TokenHash:  accountID + "-session-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
		ChallengeIDHash: accountID + "-challenge",
		AccountID:       accountID,
		CreatedAt:       now,
		ExpiresAt:       now.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("create totp challenge: %v", err)
	}
	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: accountID,
		TokenHash: accountID + "-token",
		CreatedAt: now,
		ExpiresAt: tokenExpiresAt,
	}, "old-recovery-hash"); err != nil {
		t.Fatalf("create reset token: %v", err)
	}
}

func countRows(t *testing.T, store *Store, table string, accountID string) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM `+table+` WHERE account_id = ?`, // #nosec G202 -- table is a test-fixture constant
		accountID,
	).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestResetAccountCredentialsAppliesEverythingAtOnce(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedResetAccount(t, store, "target", now.Add(30*time.Minute))
	seedResetAccount(t, store, "bystander", now.Add(30*time.Minute))

	accountID, err := store.ResetAccountCredentials(ctx, "target-token", now, "new-password-hash", "new-recovery-hash")
	if err != nil {
		t.Fatalf("reset account credentials: %v", err)
	}
	if accountID != "target" {
		t.Fatalf("expected account id target, got %q", accountID)
	}

	account, err := store.FindAccountByID(ctx, "target")
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.PasswordHash != "new-password-hash" || account.RecoveryCodeHash != "new-recovery-hash" {
		t.Fatalf("expected rotated hashes, got %#v", account)
	}
	if account.TOTPEnabled || account.TOTPSecretEncrypted != "" || account.TOTPLastUsedStep != 0 {
		t.Fatalf("expected TOTP cleared, got %#v", account)
	}
	for _, table := range []string{"sessions", "totp_challenges", "password_reset_tokens"} {
		if n := countRows(t, store, table, "target"); n != 0 {
			t.Fatalf("expected no %s rows for target, got %d", table, n)
		}
		if n := countRows(t, store, table, "bystander"); n != 1 {
			t.Fatalf("expected bystander %s row untouched, got %d", table, n)
		}
	}
	bystander, err := store.FindAccountByID(ctx, "bystander")
	if err != nil {
		t.Fatalf("find bystander: %v", err)
	}
	if bystander.PasswordHash != "old-password-hash" || !bystander.TOTPEnabled {
		t.Fatalf("expected bystander account untouched, got %#v", bystander)
	}

	if _, err := store.ResetAccountCredentials(ctx, "target-token", now, "again", "again"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a used token to be rejected, got %v", err)
	}
}

func TestResetAccountCredentialsRejectsUnusableTokens(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedResetAccount(t, store, "expired", now.Add(-time.Minute))

	for name, tokenHash := range map[string]string{
		"unknown token": "no-such-token",
		"expired token": "expired-token",
	} {
		if _, err := store.ResetAccountCredentials(ctx, tokenHash, now, "new", "new"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: expected ErrNotFound, got %v", name, err)
		}
	}
	account, err := store.FindAccountByID(ctx, "expired")
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.PasswordHash != "old-password-hash" || !account.TOTPEnabled {
		t.Fatalf("expected a rejected token to change nothing, got %#v", account)
	}
}

// A token orphaned by an account row deleted without cascade finds no account
// to update; the rollback leaves the token unconsumed.
func TestResetAccountCredentialsOrphanedTokenRollsBack(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedResetAccount(t, store, "target", now.Add(30*time.Minute))

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`DELETE FROM accounts WHERE id = ?`, "target"); err != nil {
		t.Fatalf("delete account row: %v", err)
	}

	if _, err := store.ResetAccountCredentials(ctx, "target-token", now, "new", "new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an orphaned token, got %v", err)
	}
	var consumed sql.NullString
	if err := raw.QueryRow(`SELECT consumed_at FROM password_reset_tokens WHERE token_hash = ?`, "target-token").Scan(&consumed); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if consumed.Valid {
		t.Fatal("expected the orphaned token left unconsumed after rollback")
	}
}

func TestResetAccountCredentialsRollsBackOnCleanupFailure(t *testing.T) {
	for _, table := range []string{"totp_challenges", "sessions"} {
		t.Run(table, func(t *testing.T) {
			store, dbPath := newFileBackedTestStore(t)
			ctx := context.Background()
			now := time.Now().UTC()
			seedResetAccount(t, store, "target", now.Add(30*time.Minute))

			dropTable(t, dbPath, table)

			if _, err := store.ResetAccountCredentials(ctx, "target-token", now, "new", "new"); err == nil || errors.Is(err, ErrNotFound) {
				t.Fatalf("expected a store-failure error, got %v", err)
			}
			account, err := store.FindAccountByID(ctx, "target")
			if err != nil {
				t.Fatalf("find account: %v", err)
			}
			if account.PasswordHash != "old-password-hash" || account.RecoveryCodeHash != "old-recovery-hash" ||
				!account.TOTPEnabled || account.TOTPLastUsedStep != 42 {
				t.Fatalf("expected the account unchanged after rollback, got %#v", account)
			}
			var consumed sql.NullString
			if err := store.db.QueryRow(`SELECT consumed_at FROM password_reset_tokens WHERE token_hash = ?`, "target-token").Scan(&consumed); err != nil {
				t.Fatalf("read token: %v", err)
			}
			if consumed.Valid {
				t.Fatal("expected the token left unconsumed after rollback")
			}
		})
	}
}

func TestResetAccountCredentialsSurfacesStoreErrors(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		if _, err := store.ResetAccountCredentials(context.Background(), "t", time.Now(), "p", "r"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("expected a store-failure error, got %v", err)
		}
	})

	// Dropping one column the account UPDATE names keeps accounts(id) for the
	// token's foreign key, so the consume succeeds and the UPDATE fails.
	t.Run("account update fails", func(t *testing.T) {
		store, dbPath := newFileBackedTestStore(t)
		now := time.Now().UTC()
		seedResetAccount(t, store, "target", now.Add(30*time.Minute))
		raw, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open raw sqlite: %v", err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
			t.Fatalf("configure raw sqlite: %v", err)
		}
		if _, err := raw.Exec(`ALTER TABLE accounts DROP COLUMN totp_last_used_step`); err != nil {
			t.Fatalf("drop accounts.totp_last_used_step: %v", err)
		}
		if _, err := store.ResetAccountCredentials(context.Background(), "target-token", now, "p", "r"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("expected a store-failure error, got %v", err)
		}
	})

	t.Run("password_reset_tokens dropped", func(t *testing.T) {
		store, dbPath := newFileBackedTestStore(t)
		dropTable(t, dbPath, "password_reset_tokens")
		if _, err := store.ResetAccountCredentials(context.Background(), "t", time.Now(), "p", "r"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("expected a store-failure error, got %v", err)
		}
	})
}
