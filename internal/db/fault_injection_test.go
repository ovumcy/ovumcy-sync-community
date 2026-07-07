package db

// Fault-injection coverage for internal/db error branches (#42, follow-up
// to #28). Every repository method below is wired into real production
// callers in internal/services (AuthService / TOTPService) but previously
// had no internal/db-level test at all, so its generic ExecContext /
// QueryRowContext error-wrapping branch — and, for a few, its happy path —
// sat uncovered. These tests use the same real-failure-injection style as
// the internal/api harness added in PR #32 (newFileBackedTestStore +
// dropTable: a second raw connection drops exactly the table a method
// needs, leaving every other table intact), adapted to call *Store methods
// directly instead of going through HTTP. No production code changes, no
// fake driver, no weakened invariant.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func seedFaultInjectionAccount(t *testing.T, store *Store, accountID string) models.Account {
	t.Helper()

	account, err := store.CreateAccount(context.Background(), models.Account{
		ID:           accountID,
		Login:        accountID + "@example.com",
		PasswordHash: "hash",
		Mode:         "self_hosted",
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed account %s: %v", accountID, err)
	}
	return account
}

// TestAccountFieldUpdatesHappyPathAndNotFound exercises the success and
// not-found branches of the three account-field update methods
// (UpdateAccountPasswordHash, UpdateAccountPasswordAndRecoveryHash,
// UpdateAccountRecoveryCodeHash), all previously at 0% because internal/db
// itself never called them (only internal/services did, through its own
// mocked/live store in that package's tests). Multi-account isolation is
// asserted: updating one account's fields must not touch a bystander
// account's row.
func TestAccountFieldUpdatesHappyPathAndNotFound(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	target := seedFaultInjectionAccount(t, store, "account-target")
	bystander := seedFaultInjectionAccount(t, store, "account-bystander")

	if err := store.UpdateAccountPasswordHash(ctx, target.ID, "rotated-hash"); err != nil {
		t.Fatalf("update account password hash: %v", err)
	}
	updated, err := store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account after password update: %v", err)
	}
	if updated.PasswordHash != "rotated-hash" {
		t.Fatalf("expected rotated password hash, got %#v", updated)
	}
	untouched, err := store.FindAccountByID(ctx, bystander.ID)
	if err != nil {
		t.Fatalf("find bystander account: %v", err)
	}
	if untouched.PasswordHash != bystander.PasswordHash {
		t.Fatalf("expected bystander password hash untouched, got %#v", untouched)
	}

	if err := store.UpdateAccountPasswordAndRecoveryHash(ctx, target.ID, "rotated-hash-2", "rotated-recovery-hash"); err != nil {
		t.Fatalf("update account password and recovery hash: %v", err)
	}
	updated, err = store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account after password+recovery update: %v", err)
	}
	if updated.PasswordHash != "rotated-hash-2" || updated.RecoveryCodeHash != "rotated-recovery-hash" {
		t.Fatalf("expected rotated password+recovery hash, got %#v", updated)
	}

	if err := store.UpdateAccountRecoveryCodeHash(ctx, target.ID, "rotated-recovery-hash-2"); err != nil {
		t.Fatalf("update account recovery code hash: %v", err)
	}
	updated, err = store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account after recovery-only update: %v", err)
	}
	if updated.RecoveryCodeHash != "rotated-recovery-hash-2" {
		t.Fatalf("expected rotated recovery hash, got %#v", updated)
	}

	if err := store.UpdateAccountPasswordHash(ctx, "missing-account", "any-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account password update, got %v", err)
	}
	if err := store.UpdateAccountPasswordAndRecoveryHash(ctx, "missing-account", "any-hash", "any-recovery-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account password+recovery update, got %v", err)
	}
	if err := store.UpdateAccountRecoveryCodeHash(ctx, "missing-account", "any-recovery-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account recovery update, got %v", err)
	}
}

// TestCreateAccountReturnsErrorWhenAccountsTableIsDropped exercises
// CreateAccount's generic ExecContext-error branch (distinct from its
// isUniqueConstraint -> ErrConflict branch, already covered by
// TestAccountRepositoryConflictAndLookups in repositories_test.go). The
// table must be dropped before any account is seeded, since
// seedFaultInjectionAccount itself calls CreateAccount.
func TestCreateAccountReturnsErrorWhenAccountsTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()

	dropTable(t, dbPath, "accounts")

	if _, err := store.CreateAccount(ctx, models.Account{
		ID:           "account-target",
		Login:        "account-target@example.com",
		PasswordHash: "hash",
		Mode:         "self_hosted",
		CreatedAt:    time.Now().UTC(),
	}); err == nil {
		t.Fatal("expected error creating account after accounts table is dropped")
	} else if errors.Is(err, ErrConflict) {
		t.Fatalf("expected a store-failure error, not ErrConflict, got %v", err)
	}
}

// TestAccountFieldUpdatesReturnErrorWhenAccountsTableIsDropped exercises the
// generic ExecContext-error branch of the three account-field update
// methods by dropping the accounts table out from under a live store.
func TestAccountFieldUpdatesReturnErrorWhenAccountsTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	dropTable(t, dbPath, "accounts")

	if err := store.UpdateAccountPasswordHash(ctx, target.ID, "any-hash"); err == nil {
		t.Fatal("expected error updating password hash after accounts table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}

	if err := store.UpdateAccountPasswordAndRecoveryHash(ctx, target.ID, "any-hash", "any-recovery-hash"); err == nil {
		t.Fatal("expected error updating password+recovery hash after accounts table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}

	if err := store.UpdateAccountRecoveryCodeHash(ctx, target.ID, "any-recovery-hash"); err == nil {
		t.Fatal("expected error updating recovery hash after accounts table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}
}

// TestTOTPAccountFieldMethodsHappyPathAndNotFound covers
// UpdateTOTPSecretAndEnabled, SetTOTPEnabled, and ClaimTOTPStep, all
// previously at 0%. ClaimTOTPStep's CAS semantics (only a strictly greater
// step is claimed) are asserted directly at the repository level, matching
// the no-replay invariant documented on the method.
func TestTOTPAccountFieldMethodsHappyPathAndNotFound(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	target := seedFaultInjectionAccount(t, store, "account-target")
	bystander := seedFaultInjectionAccount(t, store, "account-bystander")

	if err := store.UpdateTOTPSecretAndEnabled(ctx, target.ID, "encrypted-secret-placeholder", false); err != nil {
		t.Fatalf("update totp secret and enabled: %v", err)
	}
	afterSecret, err := store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account after totp secret update: %v", err)
	}
	if afterSecret.TOTPSecretEncrypted != "encrypted-secret-placeholder" || afterSecret.TOTPEnabled {
		t.Fatalf("expected pending totp secret with enabled=false, got %#v", afterSecret)
	}

	claimed, err := store.ClaimTOTPStep(ctx, target.ID, 100)
	if err != nil {
		t.Fatalf("claim totp step: %v", err)
	}
	if !claimed {
		t.Fatal("expected first claim at step 100 to succeed")
	}

	// Replay of the same step must be rejected (CAS requires strictly
	// greater), pinning the no-replay invariant at the repository layer.
	replayed, err := store.ClaimTOTPStep(ctx, target.ID, 100)
	if err != nil {
		t.Fatalf("replay claim totp step: %v", err)
	}
	if replayed {
		t.Fatal("expected replayed claim at the same step to be rejected")
	}

	// A lower step (clock skew / stale challenge) is also rejected.
	stale, err := store.ClaimTOTPStep(ctx, target.ID, 99)
	if err != nil {
		t.Fatalf("stale claim totp step: %v", err)
	}
	if stale {
		t.Fatal("expected a lower step claim to be rejected")
	}

	if err := store.SetTOTPEnabled(ctx, target.ID, true); err != nil {
		t.Fatalf("set totp enabled: %v", err)
	}
	afterEnable, err := store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account after totp enable: %v", err)
	}
	if !afterEnable.TOTPEnabled {
		t.Fatal("expected totp_enabled to be true after SetTOTPEnabled")
	}
	// SetTOTPEnabled must not disturb the step already claimed above (the
	// enrollment code must stay unreplayable across the enable transition).
	if afterEnable.TOTPLastUsedStep != 100 {
		t.Fatalf("expected claimed step to survive SetTOTPEnabled, got %d", afterEnable.TOTPLastUsedStep)
	}

	untouchedBystander, err := store.FindAccountByID(ctx, bystander.ID)
	if err != nil {
		t.Fatalf("find bystander account: %v", err)
	}
	if untouchedBystander.TOTPEnabled || untouchedBystander.TOTPSecretEncrypted != "" || untouchedBystander.TOTPLastUsedStep != 0 {
		t.Fatalf("expected bystander totp fields untouched, got %#v", untouchedBystander)
	}

	if err := store.UpdateTOTPSecretAndEnabled(ctx, "missing-account", "secret", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account totp secret update, got %v", err)
	}
	if err := store.SetTOTPEnabled(ctx, "missing-account", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account totp enable, got %v", err)
	}
	if claimed, err := store.ClaimTOTPStep(ctx, "missing-account", 1); err != nil || claimed {
		t.Fatalf("expected claim on missing account to report claimed=false, err=nil, got claimed=%v err=%v", claimed, err)
	}
}

// TestTOTPAccountFieldMethodsReturnErrorWhenAccountsTableIsDropped exercises
// the generic ExecContext-error branch of UpdateTOTPSecretAndEnabled,
// SetTOTPEnabled, and ClaimTOTPStep.
func TestTOTPAccountFieldMethodsReturnErrorWhenAccountsTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	dropTable(t, dbPath, "accounts")

	if err := store.UpdateTOTPSecretAndEnabled(ctx, target.ID, "secret", true); err == nil {
		t.Fatal("expected error updating totp secret after accounts table is dropped")
	}
	if err := store.SetTOTPEnabled(ctx, target.ID, true); err == nil {
		t.Fatal("expected error enabling totp after accounts table is dropped")
	}
	if _, err := store.ClaimTOTPStep(ctx, target.ID, 1); err == nil {
		t.Fatal("expected error claiming totp step after accounts table is dropped")
	}
}

// TestTOTPChallengeAttemptAndDeleteMethods covers
// IncrementTOTPChallengeFailedAttempts, DeleteTOTPChallengeByHash, and
// DeleteTOTPChallengesForAccount, all previously at 0%. Multi-account
// isolation is asserted for DeleteTOTPChallengesForAccount: clearing one
// account's challenges must not touch another account's pending challenge.
func TestTOTPChallengeAttemptAndDeleteMethods(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	target := seedFaultInjectionAccount(t, store, "account-target")
	bystander := seedFaultInjectionAccount(t, store, "account-bystander")

	targetChallenge := models.TOTPChallenge{
		ChallengeIDHash: "target-challenge-hash",
		AccountID:       target.ID,
		CreatedAt:       now,
		ExpiresAt:       now.Add(5 * time.Minute),
	}
	if err := store.UpsertTOTPChallenge(ctx, targetChallenge); err != nil {
		t.Fatalf("upsert target challenge: %v", err)
	}
	bystanderChallenge := models.TOTPChallenge{
		ChallengeIDHash: "bystander-challenge-hash",
		AccountID:       bystander.ID,
		CreatedAt:       now,
		ExpiresAt:       now.Add(5 * time.Minute),
	}
	if err := store.UpsertTOTPChallenge(ctx, bystanderChallenge); err != nil {
		t.Fatalf("upsert bystander challenge: %v", err)
	}

	firstCount, err := store.IncrementTOTPChallengeFailedAttempts(ctx, targetChallenge.ChallengeIDHash)
	if err != nil {
		t.Fatalf("increment failed attempts: %v", err)
	}
	if firstCount != 1 {
		t.Fatalf("expected first increment to report 1, got %d", firstCount)
	}
	secondCount, err := store.IncrementTOTPChallengeFailedAttempts(ctx, targetChallenge.ChallengeIDHash)
	if err != nil {
		t.Fatalf("increment failed attempts again: %v", err)
	}
	if secondCount != 2 {
		t.Fatalf("expected second increment to report 2, got %d", secondCount)
	}

	if _, err := store.IncrementTOTPChallengeFailedAttempts(ctx, "missing-challenge-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound incrementing a missing challenge, got %v", err)
	}

	if err := store.DeleteTOTPChallengeByHash(ctx, targetChallenge.ChallengeIDHash); err != nil {
		t.Fatalf("delete target challenge by hash: %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, targetChallenge.ChallengeIDHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected target challenge gone, got %v", err)
	}
	// Deleting an already-gone / unknown challenge hash is a no-op success,
	// matching the DELETE-with-no-match semantics used throughout the
	// TOTP challenge lifecycle (single-use, best-effort cleanup calls).
	if err := store.DeleteTOTPChallengeByHash(ctx, "missing-challenge-hash"); err != nil {
		t.Fatalf("expected no-op success deleting a missing challenge, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, bystanderChallenge.ChallengeIDHash); err != nil {
		t.Fatalf("expected bystander challenge to remain after target delete, got %v", err)
	}

	// Re-seed a second target challenge to exercise
	// DeleteTOTPChallengesForAccount's bulk-clear-by-account semantics.
	secondTargetChallenge := models.TOTPChallenge{
		ChallengeIDHash: "target-challenge-hash-2",
		AccountID:       target.ID,
		CreatedAt:       now,
		ExpiresAt:       now.Add(5 * time.Minute),
	}
	if err := store.UpsertTOTPChallenge(ctx, secondTargetChallenge); err != nil {
		t.Fatalf("upsert second target challenge: %v", err)
	}

	if err := store.DeleteTOTPChallengesForAccount(ctx, target.ID); err != nil {
		t.Fatalf("delete challenges for account: %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, secondTargetChallenge.ChallengeIDHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected all target challenges gone, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, bystanderChallenge.ChallengeIDHash); err != nil {
		t.Fatalf("expected bystander challenge to survive account-scoped delete, got %v", err)
	}

	// Deleting challenges for an account with none is a no-op success.
	if err := store.DeleteTOTPChallengesForAccount(ctx, target.ID); err != nil {
		t.Fatalf("expected no-op success clearing an already-empty account, got %v", err)
	}
}

// TestTOTPChallengeMethodsReturnErrorWhenChallengeTableIsDropped exercises
// the generic ExecContext/QueryRowContext-error branches of
// IncrementTOTPChallengeFailedAttempts, DeleteTOTPChallengeByHash, and
// DeleteTOTPChallengesForAccount.
func TestTOTPChallengeMethodsReturnErrorWhenChallengeTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
		ChallengeIDHash: "target-challenge-hash",
		AccountID:       target.ID,
		CreatedAt:       time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert challenge: %v", err)
	}

	dropTable(t, dbPath, "totp_challenges")

	if _, err := store.IncrementTOTPChallengeFailedAttempts(ctx, "target-challenge-hash"); err == nil {
		t.Fatal("expected error incrementing failed attempts after totp_challenges table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}

	if err := store.DeleteTOTPChallengeByHash(ctx, "target-challenge-hash"); err == nil {
		t.Fatal("expected error deleting challenge by hash after totp_challenges table is dropped")
	}

	if err := store.DeleteTOTPChallengesForAccount(ctx, target.ID); err == nil {
		t.Fatal("expected error deleting challenges for account after totp_challenges table is dropped")
	}

	if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
		ChallengeIDHash: "another-challenge-hash",
		AccountID:       target.ID,
		CreatedAt:       time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(5 * time.Minute),
	}); err == nil {
		t.Fatal("expected error upserting a challenge after totp_challenges table is dropped")
	}

	if _, err := store.FindTOTPChallengeByHash(ctx, "target-challenge-hash"); err == nil {
		t.Fatal("expected error finding a challenge after totp_challenges table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}
}

// TestPasswordResetTokenLifecycleAndAccountScopedDelete covers
// DeletePasswordResetTokensForAccount (previously 0%) plus
// ConsumePasswordResetToken's CAS edges (already-consumed, expired) that
// were not yet directly asserted at the repository level.
func TestPasswordResetTokenLifecycleAndAccountScopedDelete(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	target := seedFaultInjectionAccount(t, store, "account-target")
	bystander := seedFaultInjectionAccount(t, store, "account-bystander")

	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: target.ID,
		TokenHash: "target-reset-token-hash",
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert target reset token: %v", err)
	}
	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: bystander.ID,
		TokenHash: "bystander-reset-token-hash",
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert bystander reset token: %v", err)
	}

	// Consuming the token once succeeds; consuming it again (already
	// consumed) must report ErrNotFound rather than silently succeeding a
	// second time (single-use CAS).
	if _, err := store.ConsumePasswordResetToken(ctx, "target-reset-token-hash", now); err != nil {
		t.Fatalf("consume target reset token: %v", err)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, "target-reset-token-hash", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound consuming an already-consumed token, got %v", err)
	}

	// An expired, unconsumed token must also be rejected by the CAS.
	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: target.ID,
		TokenHash: "target-expired-token-hash",
		CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("upsert expired reset token: %v", err)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, "target-expired-token-hash", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound consuming an expired token, got %v", err)
	}

	if err := store.DeletePasswordResetTokensForAccount(ctx, bystander.ID); err != nil {
		t.Fatalf("delete reset tokens for bystander: %v", err)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, "bystander-reset-token-hash", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected bystander reset token gone after account-scoped delete, got %v", err)
	}

	// Deleting reset tokens for an account with none is a no-op success.
	if err := store.DeletePasswordResetTokensForAccount(ctx, target.ID); err != nil {
		t.Fatalf("expected no-op success clearing reset tokens with an expired/consumed remainder, got %v", err)
	}
}

// TestPasswordResetTokenMethodsReturnErrorWhenTableIsDropped exercises the
// generic ExecContext/QueryRowContext-error branches of
// DeletePasswordResetTokensForAccount and ConsumePasswordResetToken.
func TestPasswordResetTokenMethodsReturnErrorWhenTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: target.ID,
		TokenHash: "target-reset-token-hash",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert reset token: %v", err)
	}

	dropTable(t, dbPath, "password_reset_tokens")

	if err := store.DeletePasswordResetTokensForAccount(ctx, target.ID); err == nil {
		t.Fatal("expected error deleting reset tokens after password_reset_tokens table is dropped")
	}

	if _, err := store.ConsumePasswordResetToken(ctx, "target-reset-token-hash", time.Now().UTC()); err == nil {
		t.Fatal("expected error consuming reset token after password_reset_tokens table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}

	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: target.ID,
		TokenHash: "another-reset-token-hash",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
	}); err == nil {
		t.Fatal("expected error upserting a reset token after password_reset_tokens table is dropped")
	}
}

// TestSessionBulkDeleteMethodsAreAccountScoped covers
// DeleteSessionsForAccountExcept and DeleteAllSessionsForAccount (both
// previously 0%), asserting the account-scoping and keep-current-session
// semantics that AuthService/TOTPService rely on for "revoke other
// sessions" (password change, TOTP enroll) versus "revoke all sessions"
// (password reset, TOTP disable).
func TestSessionBulkDeleteMethodsAreAccountScoped(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	target := seedFaultInjectionAccount(t, store, "account-target")
	bystander := seedFaultInjectionAccount(t, store, "account-bystander")

	currentSession := models.Session{
		ID:         "target-session-current",
		AccountID:  target.ID,
		TokenHash:  "target-token-current",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	otherSession := models.Session{
		ID:         "target-session-other",
		AccountID:  target.ID,
		TokenHash:  "target-token-other",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	bystanderSession := models.Session{
		ID:         "bystander-session",
		AccountID:  bystander.ID,
		TokenHash:  "bystander-token",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	for _, session := range []models.Session{currentSession, otherSession, bystanderSession} {
		if _, err := store.CreateSession(ctx, session); err != nil {
			t.Fatalf("create session %s: %v", session.ID, err)
		}
	}

	if err := store.DeleteSessionsForAccountExcept(ctx, target.ID, currentSession.TokenHash); err != nil {
		t.Fatalf("delete sessions except current: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, currentSession.TokenHash); err != nil {
		t.Fatalf("expected current session to survive, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, otherSession.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected other target session to be revoked, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, bystanderSession.TokenHash); err != nil {
		t.Fatalf("expected bystander session to survive target's except-delete, got %v", err)
	}

	if err := store.DeleteAllSessionsForAccount(ctx, target.ID); err != nil {
		t.Fatalf("delete all sessions for target: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, currentSession.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected current session to be revoked by delete-all, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, bystanderSession.TokenHash); err != nil {
		t.Fatalf("expected bystander session to survive target's delete-all, got %v", err)
	}

	// Both bulk deletes are no-op successes when the account already has no
	// sessions left.
	if err := store.DeleteSessionsForAccountExcept(ctx, target.ID, "any-token-hash"); err != nil {
		t.Fatalf("expected no-op success on except-delete with no sessions, got %v", err)
	}
	if err := store.DeleteAllSessionsForAccount(ctx, target.ID); err != nil {
		t.Fatalf("expected no-op success on delete-all with no sessions, got %v", err)
	}
}

// TestSessionBulkDeleteMethodsReturnErrorWhenSessionsTableIsDropped
// exercises the generic ExecContext-error branch of
// DeleteSessionsForAccountExcept and DeleteAllSessionsForAccount.
func TestSessionBulkDeleteMethodsReturnErrorWhenSessionsTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	dropTable(t, dbPath, "sessions")

	if err := store.DeleteSessionsForAccountExcept(ctx, target.ID, "any-token-hash"); err == nil {
		t.Fatal("expected error on except-delete after sessions table is dropped")
	}
	if err := store.DeleteAllSessionsForAccount(ctx, target.ID); err == nil {
		t.Fatal("expected error on delete-all after sessions table is dropped")
	}
}

// TestFindDeviceReturnsNotFoundForMissingDevice exercises scanDevice's
// sql.ErrNoRows branch (the only branch of scanDevice not already covered
// via the happy-path device tests in migrations_bootstrap_test.go).
func TestFindDeviceReturnsNotFoundForMissingDevice(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	if _, err := store.FindDevice(ctx, target.ID, "missing-device"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing device, got %v", err)
	}
}

// TestManagedAccountUpsertConflictOnLoginAcrossDifferentIDs exercises
// UpsertManagedAccount's isUniqueConstraint branch: the ON CONFLICT clause
// only covers a conflict on id, so a second managed account reusing an
// existing login under a different id must surface ErrConflict rather than
// silently overwriting the identity the login belongs to.
func TestManagedAccountUpsertConflictOnLoginAcrossDifferentIDs(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := store.UpsertManagedAccount(ctx, models.Account{
		ID:           "managedacct0001",
		Login:        "managed:managedacct0001",
		PasswordHash: "managed_service_only",
		Mode:         "managed",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("create first managed account: %v", err)
	}

	if _, err := store.UpsertManagedAccount(ctx, models.Account{
		ID:           "managedacct0002",
		Login:        "managed:managedacct0001",
		PasswordHash: "managed_service_only",
		Mode:         "managed",
		CreatedAt:    now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for login collision across different ids, got %v", err)
	}
}

// TestManagedAccountUpsertReturnsErrorWhenAccountsTableIsDropped exercises
// UpsertManagedAccount's generic ExecContext-error branch.
func TestManagedAccountUpsertReturnsErrorWhenAccountsTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()

	dropTable(t, dbPath, "accounts")

	if _, err := store.UpsertManagedAccount(ctx, models.Account{
		ID:           "managedacct0001",
		Login:        "managed:managedacct0001",
		PasswordHash: "managed_service_only",
		Mode:         "managed",
		CreatedAt:    time.Now().UTC(),
	}); err == nil {
		t.Fatal("expected error upserting managed account after accounts table is dropped")
	} else if errors.Is(err, ErrConflict) {
		t.Fatalf("expected a store-failure error, not ErrConflict, got %v", err)
	}
}

// TestMustParseTimeAcceptsSQLiteDefaultTimestampFormat exercises
// mustParseTime's fallback format branch. Every repository write path in
// this package formats timestamps via time.RFC3339Nano before persisting,
// so the "2006-01-02 15:04:05" branch (SQLite's own CURRENT_TIMESTAMP
// format) is never produced by a write path today; it exists as a
// defensive fallback for data written by a different SQLite default. This
// test asserts that fallback contract directly at the unit level, since
// there is no reachable write path to fault it through the repository
// methods themselves.
func TestMustParseTimeAcceptsSQLiteDefaultTimestampFormat(t *testing.T) {
	parsed := mustParseTime("2024-03-15 10:30:00")
	if parsed.IsZero() {
		t.Fatal("expected a non-zero parsed time for the sqlite default timestamp format")
	}
	if parsed.Year() != 2024 || parsed.Month() != time.March || parsed.Day() != 15 {
		t.Fatalf("unexpected parsed date: %v", parsed)
	}
}

// TestUpsertEncryptedBlobRejectsStaleGeneration exercises
// UpsertEncryptedBlob's CAS-rejection branch directly: once a blob exists
// at generation N, a write at generation <= N must be rejected as
// ErrStaleGeneration (RowsAffected == 0 on the conflict-update branch)
// rather than silently overwriting fresher data, and a write at generation
// > N must succeed. This is the CAS the doc comment on UpsertEncryptedBlob
// documents; it had no direct repository-level test before this file.
func TestUpsertEncryptedBlobRejectsStaleGeneration(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")
	now := time.Now().UTC()

	if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
		AccountID:      target.ID,
		SchemaVersion:  1,
		Generation:     5,
		ChecksumSHA256: strings.Repeat("a", 64),
		Ciphertext:     []byte("ciphertext-gen-5"),
		CiphertextSize: len("ciphertext-gen-5"),
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("upsert blob at generation 5: %v", err)
	}

	// Equal generation is rejected (not strictly greater).
	if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
		AccountID:      target.ID,
		SchemaVersion:  1,
		Generation:     5,
		ChecksumSHA256: strings.Repeat("b", 64),
		Ciphertext:     []byte("ciphertext-replay"),
		CiphertextSize: len("ciphertext-replay"),
		UpdatedAt:      now,
	}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected ErrStaleGeneration for an equal generation, got %v", err)
	}

	// Lower generation (a concurrent loser) is rejected too.
	if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
		AccountID:      target.ID,
		SchemaVersion:  1,
		Generation:     3,
		ChecksumSHA256: strings.Repeat("c", 64),
		Ciphertext:     []byte("ciphertext-stale"),
		CiphertextSize: len("ciphertext-stale"),
		UpdatedAt:      now,
	}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected ErrStaleGeneration for a lower generation, got %v", err)
	}

	// The persisted blob must still be the generation-5 write; a rejected
	// CAS must not have partially applied.
	persisted, err := store.GetEncryptedBlob(ctx, target.ID)
	if err != nil {
		t.Fatalf("get blob after rejected writes: %v", err)
	}
	if persisted.Generation != 5 || string(persisted.Ciphertext) != "ciphertext-gen-5" {
		t.Fatalf("expected generation-5 blob to survive rejected CAS writes, got %#v", persisted)
	}

	// A strictly greater generation succeeds and replaces the row.
	if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
		AccountID:      target.ID,
		SchemaVersion:  1,
		Generation:     6,
		ChecksumSHA256: strings.Repeat("d", 64),
		Ciphertext:     []byte("ciphertext-gen-6"),
		CiphertextSize: len("ciphertext-gen-6"),
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("upsert blob at generation 6: %v", err)
	}
	advanced, err := store.GetEncryptedBlob(ctx, target.ID)
	if err != nil {
		t.Fatalf("get blob after advancing generation: %v", err)
	}
	if advanced.Generation != 6 || string(advanced.Ciphertext) != "ciphertext-gen-6" {
		t.Fatalf("expected generation-6 blob after a valid CAS write, got %#v", advanced)
	}
}

// TestBlobAndRecoveryUpsertsReturnErrorWhenTablesAreDropped exercises the
// generic ExecContext-error branch of UpsertEncryptedBlob and
// UpsertRecoveryKeyPackage. UpsertEncryptedBlob's RowsAffected() error
// branch is not reachable from this table-drop technique (the ExecContext
// call itself fails first, before RowsAffected is ever called) — see
// Deviations in the PR description for why that branch needs a fake driver.
func TestBlobAndRecoveryUpsertsReturnErrorWhenTablesAreDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")
	now := time.Now().UTC()

	dropTable(t, dbPath, "encrypted_blobs")

	if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
		AccountID:      target.ID,
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: strings.Repeat("a", 64),
		Ciphertext:     []byte("ciphertext"),
		CiphertextSize: len("ciphertext"),
		UpdatedAt:      now,
	}); err == nil {
		t.Fatal("expected error upserting blob after encrypted_blobs table is dropped")
	} else if errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected a store-failure error, not ErrStaleGeneration, got %v", err)
	}

	if _, err := store.GetEncryptedBlob(ctx, target.ID); err == nil {
		t.Fatal("expected error getting blob after encrypted_blobs table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}

	dropTable(t, dbPath, "recovery_key_packages")

	if _, err := store.UpsertRecoveryKeyPackage(ctx, models.RecoveryKeyPackage{
		AccountID:            target.ID,
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("b", 48),
		WrappedMasterKeyHex:  strings.Repeat("c", 96),
		PhraseFingerprintHex: strings.Repeat("d", 16),
		UpdatedAt:            now,
	}); err == nil {
		t.Fatal("expected error upserting recovery key package after recovery_key_packages table is dropped")
	}

	if _, err := store.GetRecoveryKeyPackage(ctx, target.ID); err == nil {
		t.Fatal("expected error getting recovery key package after recovery_key_packages table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}
}

// TestDeviceAndSessionQueriesReturnErrorWhenTablesAreDropped exercises the
// generic error branches of CountDevicesForAccount, UpsertDevice,
// CreateSession, and TouchSession that dropTable-based tests elsewhere in
// this file do not already reach.
func TestDeviceAndSessionQueriesReturnErrorWhenTablesAreDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")
	now := time.Now().UTC()

	dropTable(t, dbPath, "devices")

	if _, err := store.CountDevicesForAccount(ctx, target.ID); err == nil {
		t.Fatal("expected error counting devices after devices table is dropped")
	}
	if _, err := store.UpsertDevice(ctx, models.Device{
		DeviceID:    "device-1",
		AccountID:   target.ID,
		DeviceLabel: "Pixel 7",
		CreatedAt:   now,
		LastSeenAt:  now,
	}); err == nil {
		t.Fatal("expected error upserting device after devices table is dropped")
	}
	if _, err := store.FindDevice(ctx, target.ID, "device-1"); err == nil {
		t.Fatal("expected error finding device after devices table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}

	dropTable(t, dbPath, "sessions")

	if _, err := store.CreateSession(ctx, models.Session{
		ID:         "session-1",
		AccountID:  target.ID,
		TokenHash:  "token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}); err == nil {
		t.Fatal("expected error creating session after sessions table is dropped")
	}
	if err := store.TouchSession(ctx, "session-1", now); err == nil {
		t.Fatal("expected error touching session after sessions table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}
	if err := store.DeleteSessionByTokenHash(ctx, "token-hash"); err == nil {
		t.Fatal("expected error deleting session after sessions table is dropped")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}
}

// TestDeleteAccountReturnsErrorAndRollsBackWhenAChildTableIsDropped
// exercises DeleteAccount's per-child-table error branch inside its
// transaction loop. DeleteAccount deletes from sessions, devices,
// encrypted_blobs, recovery_key_packages, password_reset_tokens, and
// totp_challenges (in that order) before deleting the accounts row itself,
// all inside one transaction. Dropping "sessions" — the first table in the
// loop — via a second connection means the very first child delete inside
// the transaction fails, so the whole call must return an error and the
// deferred tx.Rollback() must leave every already-processed row (there are
// none yet, since sessions is first) and the account row itself untouched.
func TestDeleteAccountReturnsErrorAndRollsBackWhenAChildTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	dropTable(t, dbPath, "sessions")

	err := store.DeleteAccount(ctx, target.ID)
	if err == nil {
		t.Fatal("expected DeleteAccount to fail when a child table is dropped")
	}
	if !strings.Contains(err.Error(), "delete account sessions rows") {
		t.Fatalf("expected the sessions child-delete error to surface, got %v", err)
	}

	// The account row itself must survive: the failed child delete must not
	// have been partially committed ahead of the transaction aborting.
	if _, findErr := store.FindAccountByID(ctx, target.ID); findErr != nil {
		t.Fatalf("expected account row to survive the rolled-back delete, got %v", findErr)
	}
}

// TestScanAccountReturnsGenericErrorOnTypeMismatch exercises scanAccount's
// generic scan-error branch (distinct from its sql.ErrNoRows -> ErrNotFound
// branch, already covered by the not-found tests throughout this package).
// SQLite's column type affinity allows a non-numeric string to be stored in
// an INTEGER-affinity column via a raw connection bypassing the Go layer's
// own writes; scanning it back into premium_active's int destination then
// fails with a genuine driver type-conversion error. This is a real
// "corrupted row shape" fault — the same failure an operator's manual
// UPDATE or a foreign write into the sqlite file could produce — not a
// fake driver.
//
// scanSession has no equivalent test: every one of its columns scans into
// a Go string, and SQLite's TEXT-affinity columns accept BLOB values
// without a scan error (verified while writing this test), so there is no
// SQL-DML-only way to force scanSession's generic-error branch without a
// fake driver. Left uncovered; see Deviations in the PR description.
func TestScanAccountReturnsGenericErrorOnTypeMismatch(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

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
	if _, err := raw.Exec(`UPDATE accounts SET premium_active = 'not-a-number' WHERE id = ?`, target.ID); err != nil {
		t.Fatalf("corrupt premium_active column: %v", err)
	}

	if _, err := store.FindAccountByID(ctx, target.ID); err == nil {
		t.Fatal("expected FindAccountByID to fail scanning a corrupted premium_active column")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a scan-error, not ErrNotFound, got %v", err)
	} else if !strings.Contains(err.Error(), "scan account") {
		t.Fatalf("expected scanAccount's wrapped error, got %v", err)
	}

	if _, err := store.FindAccountByLogin(ctx, target.Login); err == nil {
		t.Fatal("expected FindAccountByLogin to fail scanning a corrupted premium_active column")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a scan-error, not ErrNotFound, got %v", err)
	}
}
