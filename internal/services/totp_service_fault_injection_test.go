package services

// Fault-injection and edge-case coverage for internal/services/totp_service.go
// (residual coverage debt: the internal/db and internal/services fault-injection
// idioms — openFileBackedTestStore + dropTable, established for the db package
// in internal/db/fault_injection_test.go and reused for managed_bridge_service.go
// — had never been applied to TOTPService's own methods). No production code
// changes; every technique here matches an existing precedent elsewhere in the
// suite (closed-store, dropped table, dropped column, raw-row corruption, and
// direct repository manipulation to set up a documented edge-case precondition).

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// newFileBackedTOTPServices mirrors fixedTOTPClock but returns a
// file-backed store (via openFileBackedTestStore) so a second raw
// connection can fault it, plus the db path for dropTable/column-drop
// helpers.
func newFileBackedTOTPServices(t *testing.T) (auth *AuthService, totp *TOTPService, dbPath string, now time.Time) {
	t.Helper()

	store, path := openFileBackedTestStore(t)
	auth = NewAuthService(store, 24*time.Hour)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp = NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)

	now = time.Date(2026, 7, 7, 10, 0, 5, 0, time.UTC)
	auth.now = func() time.Time { return now }
	totp.now = func() time.Time { return now }
	return auth, totp, path, now
}

// TestTOTPServiceRejectsWhenNotConfigured exercises the !Configured guard
// (ErrTOTPNotConfigured) on all four methods that check it. A TOTPService
// with an empty secretKey is exactly the "no FIELD_ENCRYPTION_KEY set"
// production shape.
func TestTOTPServiceRejectsWhenNotConfigured(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	unconfigured := NewTOTPService(store, auth, nil, "ovumcy-sync-community-test")
	ctx := context.Background()

	if _, err := unconfigured.StartEnrollment(ctx, "any-account", "any-password"); err != ErrTOTPNotConfigured {
		t.Fatalf("StartEnrollment: expected ErrTOTPNotConfigured, got %v", err)
	}
	if err := unconfigured.CompleteEnrollment(ctx, "any-account", "any-hash", "123456"); err != ErrTOTPNotConfigured {
		t.Fatalf("CompleteEnrollment: expected ErrTOTPNotConfigured, got %v", err)
	}
	if err := unconfigured.Disable(ctx, "any-account", "any-password", "123456"); err != ErrTOTPNotConfigured {
		t.Fatalf("Disable: expected ErrTOTPNotConfigured, got %v", err)
	}
	if _, err := unconfigured.VerifyChallenge(ctx, "any-challenge", "123456"); err != ErrTOTPNotConfigured {
		t.Fatalf("VerifyChallenge: expected ErrTOTPNotConfigured, got %v", err)
	}
}

// TestTOTPServiceMethodsSurfaceGenericErrorWhenAccountsTableIsDropped
// exercises StartEnrollment's, CompleteEnrollment's, and Disable's shared
// "FindAccountByID generic (non-ErrNotFound) error" branch: dropping the
// accounts table faults their first store call directly, the same
// dropTable technique the db package's own fault-injection tests use.
func TestTOTPServiceMethodsSurfaceGenericErrorWhenAccountsTableIsDropped(t *testing.T) {
	_, totp, dbPath, _ := newFileBackedTOTPServices(t)
	ctx := context.Background()
	dropTable(t, dbPath, "accounts")

	if _, err := totp.StartEnrollment(ctx, "account-target", "any-password"); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("StartEnrollment: expected a store-failure error, not ErrUnauthorized, got %v", err)
	}
	if err := totp.CompleteEnrollment(ctx, "account-target", "any-hash", "123456"); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("CompleteEnrollment: expected a store-failure error, not ErrUnauthorized, got %v", err)
	}
	if err := totp.Disable(ctx, "account-target", "any-password", "123456"); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Disable: expected a store-failure error, not ErrUnauthorized, got %v", err)
	}
}

// TestStartEnrollmentSurfacesNewSecretSeamFailure exercises the
// newSecret()-error branch via the service's own dependency-injection seam
// (the same seam pattern security.NewTOTPSecret's caller uses in
// production; swapping it in a test requires no production change).
func TestStartEnrollmentSurfacesNewSecretSeamFailure(t *testing.T) {
	auth, totp, _ := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	registered, err := auth.Register(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	wantErr := errors.New("boom: rand exhausted")
	totp.newSecret = func() ([]byte, error) { return nil, wantErr }

	if _, err := totp.StartEnrollment(ctx, registered.AccountID, password); !errors.Is(err, wantErr) {
		t.Fatalf("expected the seam's error to surface unwrapped, got %v", err)
	}
}

// TestCompleteEnrollmentRejectsUnknownAccountAndAlreadyEnabled covers two
// trivial, pure-logic branches: an unknown account id (ErrUnauthorized) and
// an account that already has TOTP enabled (ErrTOTPAlreadyEnabled) — neither
// needs fault injection, just a precondition that does not go through
// StartEnrollment first.
func TestCompleteEnrollmentRejectsUnknownAccountAndAlreadyEnabled(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()

	if err := totp.CompleteEnrollment(ctx, "missing-account", "any-hash", "123456"); err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for an unknown account, got %v", err)
	}

	accountID, sessionToken, _, enrollCode := enrollTOTP(t, auth, totp, now)
	if err := totp.CompleteEnrollment(ctx, accountID, security.HashToken(sessionToken), enrollCode); err != ErrTOTPAlreadyEnabled {
		t.Fatalf("expected ErrTOTPAlreadyEnabled once enrollment already completed once, got %v", err)
	}
}

// TestStartEnrollmentAndDisableRejectUnknownAccount covers the trivial
// unknown-account (ErrUnauthorized) branch for the two methods that don't
// already have a dedicated case elsewhere: StartEnrollment (unlike
// CompleteEnrollment above) and Disable. Neither needs fault injection — an
// account id that was simply never created is enough.
func TestStartEnrollmentAndDisableRejectUnknownAccount(t *testing.T) {
	_, totp, _ := fixedTOTPClock(t)
	ctx := context.Background()

	if _, err := totp.StartEnrollment(ctx, "missing-account", "any-password"); err != ErrUnauthorized {
		t.Fatalf("StartEnrollment: expected ErrUnauthorized for an unknown account, got %v", err)
	}
	if err := totp.Disable(ctx, "missing-account", "any-password", "123456"); err != ErrUnauthorized {
		t.Fatalf("Disable: expected ErrUnauthorized for an unknown account, got %v", err)
	}
}

// TestCompleteEnrollmentRejectsPreClaimedStepAsReplay exercises
// CompleteEnrollment's own ClaimTOTPStep replay branch (distinct from the
// existing TestCompleteEnrollmentStepSurvivesEnableSoLoginChallengeCannotReplay
// / …SoDisableCannotReplay tests, which replay an enrollment code against
// VerifyChallenge / Disable, not against CompleteEnrollment itself). The
// step CompleteEnrollment is about to claim is pre-claimed directly through
// the repository — a legitimate, deterministic way to reach "already
// claimed by the time ClaimTOTPStep runs" without any timing dependency.
func TestCompleteEnrollmentRejectsPreClaimedStepAsReplay(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	registered, err := auth.Register(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	start, err := totp.StartEnrollment(ctx, registered.AccountID, password)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	step := now.UTC().Unix() / security.TOTPStepSeconds
	code := security.GenerateTOTPCode(secret, step)

	// Claim the step directly through the repository before CompleteEnrollment
	// ever runs, so its own internal ClaimTOTPStep call finds it already taken.
	if claimed, err := totp.store.ClaimTOTPStep(ctx, registered.AccountID, step); err != nil || !claimed {
		t.Fatalf("pre-claim step: claimed=%v err=%v", claimed, err)
	}

	err = totp.CompleteEnrollment(ctx, registered.AccountID, security.HashToken(registered.SessionToken), code)
	if err != ErrTOTPReplayed {
		t.Fatalf("expected ErrTOTPReplayed for a pre-claimed step, got %v", err)
	}
}

// TestCompleteEnrollmentSurfacesSessionRevocationStoreError exercises
// CompleteEnrollment's DeleteSessionsForAccountExcept generic-error branch.
// Unlike the accounts-table calls earlier in this method, "sessions" is a
// different table untouched by anything before this call, so dropping it
// alone isolates exactly this step.
func TestCompleteEnrollmentSurfacesSessionRevocationStoreError(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp := NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)
	now := time.Date(2026, 7, 7, 10, 0, 5, 0, time.UTC)
	auth.now = func() time.Time { return now }
	totp.now = func() time.Time { return now }

	ctx := context.Background()
	const password = "correct horse battery staple"
	registered, err := auth.Register(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	start, err := totp.StartEnrollment(ctx, registered.AccountID, password)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	dropTable(t, dbPath, "sessions")

	step := now.UTC().Unix() / security.TOTPStepSeconds
	code := security.GenerateTOTPCode(secret, step)
	err = totp.CompleteEnrollment(ctx, registered.AccountID, security.HashToken(registered.SessionToken), code)
	if err == nil {
		t.Fatal("expected CompleteEnrollment to fail when the sessions table is dropped")
	}
	if !strings.Contains(err.Error(), "delete other sessions") {
		t.Fatalf("expected the session-revocation store error to surface, got %v", err)
	}
}

// TestDisableRejectsWrongPasswordAndWrongCode covers two more trivial,
// pure-logic branches directly (no fault injection): a correct account with
// TOTP enabled, but a wrong current password or a wrong TOTP code.
func TestDisableRejectsWrongPasswordAndWrongCode(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	if err := totp.Disable(ctx, accountID, "wrong password entirely", "000000"); err != ErrInvalidCurrentPassword {
		t.Fatalf("expected ErrInvalidCurrentPassword for a wrong password, got %v", err)
	}

	// Right password, but a code that cannot match any step in the ±1 window.
	step := now.UTC().Unix() / security.TOTPStepSeconds
	wrongCode := security.GenerateTOTPCode(secret, step+50)
	if err := totp.Disable(ctx, accountID, password, wrongCode); err != ErrTOTPInvalidCode {
		t.Fatalf("expected ErrTOTPInvalidCode for a wrong code, got %v", err)
	}
}

// TestDisableSurfacesSessionAndChallengeCleanupStoreErrorsSeparately
// exercises Disable's DeleteAllSessionsForAccount and
// DeleteTOTPChallengesForAccount generic-error branches. They run
// sequentially against different tables, so each is isolated with its own
// store and its own single dropped table — dropping "sessions" alone must
// not also need "totp_challenges" to still work, and vice versa.
func TestDisableSurfacesSessionAndChallengeCleanupStoreErrorsSeparately(t *testing.T) {
	setup := func(t *testing.T) (totp *TOTPService, accountID, sessionToken string, dbPath string, now time.Time) {
		t.Helper()
		store, path := openFileBackedTestStore(t)
		auth := NewAuthService(store, 24*time.Hour)
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		totpSvc := NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
		auth.AttachTOTPChallengeIssuer(totpSvc)
		enrollNow := time.Date(2026, 7, 7, 10, 0, 5, 0, time.UTC)
		auth.now = func() time.Time { return enrollNow }
		totpSvc.now = func() time.Time { return enrollNow }

		acctID, token, _, _ := enrollTOTP(t, auth, totpSvc, enrollNow)

		// Advance one full step past enrollment: the enrollment code's step
		// was already claimed by CompleteEnrollment, so a Disable call at
		// that same step would be rejected as ErrTOTPReplayed before ever
		// reaching the session/challenge cleanup this test targets.
		disableNow := enrollNow.Add(security.TOTPStepSeconds * time.Second)
		totpSvc.now = func() time.Time { return disableNow }
		return totpSvc, acctID, token, path, disableNow
	}

	t.Run("sessions table dropped", func(t *testing.T) {
		totp, accountID, _, dbPath, now := setup(t)
		account, err := totp.store.FindAccountByID(context.Background(), accountID)
		if err != nil {
			t.Fatalf("find account: %v", err)
		}
		secret, err := security.DecryptField(account.TOTPSecretEncrypted, totp.secretKey, aadForTOTPSecret(accountID))
		if err != nil {
			t.Fatalf("decrypt secret: %v", err)
		}

		dropTable(t, dbPath, "sessions")

		step := now.UTC().Unix() / security.TOTPStepSeconds
		code := security.GenerateTOTPCode([]byte(secret), step)
		err = totp.Disable(context.Background(), accountID, "correct horse battery staple", code)
		if err == nil {
			t.Fatal("expected Disable to fail when the sessions table is dropped")
		}
		if !strings.Contains(err.Error(), "delete all sessions") {
			t.Fatalf("expected the session-cleanup store error to surface, got %v", err)
		}
	})

	t.Run("totp_challenges table dropped", func(t *testing.T) {
		totp, accountID, _, dbPath, now := setup(t)
		account, err := totp.store.FindAccountByID(context.Background(), accountID)
		if err != nil {
			t.Fatalf("find account: %v", err)
		}
		secret, err := security.DecryptField(account.TOTPSecretEncrypted, totp.secretKey, aadForTOTPSecret(accountID))
		if err != nil {
			t.Fatalf("decrypt secret: %v", err)
		}

		dropTable(t, dbPath, "totp_challenges")

		step := now.UTC().Unix() / security.TOTPStepSeconds
		code := security.GenerateTOTPCode([]byte(secret), step)
		err = totp.Disable(context.Background(), accountID, "correct horse battery staple", code)
		if err == nil {
			t.Fatal("expected Disable to fail when the totp_challenges table is dropped")
		}
		if !strings.Contains(err.Error(), "delete totp challenge") {
			t.Fatalf("expected the challenge-cleanup store error to surface, got %v", err)
		}
	})
}

// TestDisableSurfacesDecryptFieldError exercises Disable's DecryptField
// error branch with a real corrupted-ciphertext precondition: an
// account.TOTPSecretEncrypted value that is not valid base64 (the shape
// DecryptField's own malformed-input test in field_crypto_test.go exercises
// directly). Written through the repository layer, bypassing EncryptField,
// the same way a hand-edited row or a future encoding-format bug would
// corrupt the stored ciphertext in the field.
func TestDisableSurfacesDecryptFieldError(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	accountID, _, _, _ := enrollTOTP(t, auth, totp, now)

	if err := totp.store.UpdateTOTPSecretAndEnabled(ctx, accountID, "not valid base64!!", true); err != nil {
		t.Fatalf("corrupt totp secret: %v", err)
	}
	// SetTOTPEnabled alone would reset nothing else; re-affirm enabled=true
	// (UpdateTOTPSecretAndEnabled above already set it, this just documents
	// the precondition Disable requires).
	if err := totp.store.SetTOTPEnabled(ctx, accountID, true); err != nil {
		t.Fatalf("re-affirm totp enabled: %v", err)
	}

	err := totp.Disable(ctx, accountID, password, "000000")
	if !errors.Is(err, ErrTOTPSecretDecrypt) {
		t.Fatalf("expected ErrTOTPSecretDecrypt for a corrupted secret, got %v", err)
	}
}

// dropTOTPChallengesExpiresAtColumn removes totp_challenges.expires_at out
// from under a live store through a second connection. UpsertTOTPChallenge's
// INSERT names expires_at explicitly and so fails once it is gone, while
// DeleteTOTPChallengesForAccount's `DELETE ... WHERE account_id = ?` names
// no other column and keeps working — isolating IssueChallenge's upsert step
// from its own preceding delete-existing-challenges step, both of which
// otherwise hit the same table. Mirrors internal/db's
// dropAccountsLapsedAtColumn helper (same second-connection, single-column
// technique).
func dropTOTPChallengesExpiresAtColumn(t *testing.T, dbPath string) {
	t.Helper()
	dropColumn(t, dbPath, "totp_challenges", "expires_at")
}

// dropTOTPChallengesFailedAttemptsColumn removes
// totp_challenges.failed_attempts out from under a live store.
// IncrementTOTPChallengeFailedAttempts's `UPDATE ... RETURNING
// failed_attempts` names the column explicitly and so fails once it is gone,
// while FindTOTPChallengeByHash's SELECT never names failed_attempts and
// keeps working — isolating VerifyChallenge's failed-attempt bookkeeping
// step from its own preceding challenge lookup.
func dropTOTPChallengesFailedAttemptsColumn(t *testing.T, dbPath string) {
	t.Helper()
	dropColumn(t, dbPath, "totp_challenges", "failed_attempts")
}

func dropColumn(t *testing.T, dbPath, table, column string) {
	t.Helper()

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
	if _, err := raw.Exec("ALTER TABLE " + table + " DROP COLUMN " + column); err != nil { // #nosec G202 -- table/column are test-fixture constants chosen by the test, never user input
		t.Fatalf("drop %s.%s column: %v", table, column, err)
	}
}

// TestIssueChallengeSurfacesStoreErrors exercises IssueChallenge's
// DeleteTOTPChallengesForAccount and UpsertTOTPChallenge generic-error
// branches separately, since one dropped table can only isolate one of the
// two sequential store calls at a time.
func TestIssueChallengeSurfacesStoreErrors(t *testing.T) {
	t.Run("totp_challenges table dropped fails the supersede-delete", func(t *testing.T) {
		auth, totp, dbPath, now := newFileBackedTOTPServices(t)
		ctx := context.Background()
		registered, err := auth.Register(ctx, "owner@example.com", "correct horse battery staple")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		_ = now

		dropTable(t, dbPath, "totp_challenges")

		_, _, err = totp.IssueChallenge(ctx, registered.AccountID)
		if err == nil {
			t.Fatal("expected IssueChallenge to fail when the totp_challenges table is dropped")
		}
		if !strings.Contains(err.Error(), "delete totp challenges for account") {
			t.Fatalf("expected the supersede-delete store error to surface, got %v", err)
		}
	})

	t.Run("expires_at column dropped fails the upsert", func(t *testing.T) {
		auth, totp, dbPath, now := newFileBackedTOTPServices(t)
		ctx := context.Background()
		registered, err := auth.Register(ctx, "owner@example.com", "correct horse battery staple")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		_ = now

		dropTOTPChallengesExpiresAtColumn(t, dbPath)

		_, _, err = totp.IssueChallenge(ctx, registered.AccountID)
		if err == nil {
			t.Fatal("expected IssueChallenge to fail when totp_challenges.expires_at is dropped")
		}
		if !strings.Contains(err.Error(), "insert totp challenge") {
			t.Fatalf("expected the upsert store error to surface, got %v", err)
		}
	})
}

// enrollAndChallengeTOTP registers and enrolls an account, then issues a
// real login challenge for it (password login on a TOTP-enabled account),
// returning everything a VerifyChallenge test needs.
func enrollAndChallengeTOTP(
	t *testing.T,
	auth *AuthService,
	totp *TOTPService,
	now time.Time,
) (accountID, challengeID string, secret []byte) {
	t.Helper()

	ctx := context.Background()
	const password = "correct horse battery staple"
	accountID, _, secret, _ = enrollTOTP(t, auth, totp, now)

	loginResult, err := auth.Login(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if loginResult.TOTPChallenge == nil {
		t.Fatalf("expected a TOTP challenge, got %#v", loginResult)
	}
	return accountID, loginResult.TOTPChallenge.ChallengeID, secret
}

// TestVerifyChallengeSurfacesFindChallengeStoreError exercises
// FindTOTPChallengeByHash's generic-error branch: it is VerifyChallenge's
// first store call, so dropping totp_challenges faults it directly.
func TestVerifyChallengeSurfacesFindChallengeStoreError(t *testing.T) {
	auth, totp, dbPath, now := newFileBackedTOTPServices(t)
	ctx := context.Background()
	accountID, challengeID, secret := enrollAndChallengeTOTP(t, auth, totp, now)
	_ = accountID
	_ = secret

	dropTable(t, dbPath, "totp_challenges")

	if _, err := totp.VerifyChallenge(ctx, challengeID, "000000"); err == nil {
		t.Fatal("expected VerifyChallenge to fail when the totp_challenges table is dropped")
	}
}

// TestVerifyChallengeRejectsExpiredChallenge is a trivial, pure-logic case:
// a challenge whose expires_at has already passed must be rejected as
// ErrTOTPChallengeInvalid regardless of the code offered, and the dead row
// is pruned as a side effect.
func TestVerifyChallengeRejectsExpiredChallenge(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	expiredChallenge := models.TOTPChallenge{
		ChallengeIDHash: security.HashToken("expired-challenge-id"),
		AccountID:       accountID,
		CreatedAt:       now.Add(-10 * time.Minute),
		ExpiresAt:       now.Add(-5 * time.Minute),
	}
	if err := totp.store.UpsertTOTPChallenge(ctx, expiredChallenge); err != nil {
		t.Fatalf("seed expired challenge: %v", err)
	}

	step := now.UTC().Unix() / security.TOTPStepSeconds
	code := security.GenerateTOTPCode(secret, step)
	if _, err := totp.VerifyChallenge(ctx, "expired-challenge-id", code); err != ErrTOTPChallengeInvalid {
		t.Fatalf("expected ErrTOTPChallengeInvalid for an expired challenge, got %v", err)
	}

	// The dead row must have been pruned as a side effect.
	if _, err := totp.store.FindTOTPChallengeByHash(ctx, expiredChallenge.ChallengeIDHash); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected the expired challenge row to be pruned, got %v", err)
	}
}

// TestVerifyChallengeAccountLookupEdgeCases covers the two FindAccountByID
// branches inside VerifyChallenge, both set up as deterministic static
// preconditions (not races): an orphaned challenge whose account row is
// gone (ErrNotFound -> ErrTOTPChallengeInvalid), and a generic store failure
// once the accounts table itself is gone. FindTOTPChallengeByHash's own
// SELECT never touches "accounts", so it keeps succeeding in both cases.
func TestVerifyChallengeAccountLookupEdgeCases(t *testing.T) {
	t.Run("account row deleted after the challenge was issued", func(t *testing.T) {
		auth, totp, dbPath, now := newFileBackedTOTPServices(t)
		ctx := context.Background()
		accountID, challengeID, _ := enrollAndChallengeTOTP(t, auth, totp, now)

		raw, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open raw sqlite: %v", err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
			t.Fatalf("configure raw sqlite: %v", err)
		}
		// A raw connection has foreign_keys enforcement off by default (only
		// PRAGMA busy_timeout is set above), so this delete does not cascade
		// to the still-pending challenge row — a deterministic orphan, not a
		// timing-dependent race.
		if _, err := raw.Exec(`DELETE FROM accounts WHERE id = ?`, accountID); err != nil {
			t.Fatalf("orphan the challenge by deleting its account row: %v", err)
		}

		if _, err := totp.VerifyChallenge(ctx, challengeID, "000000"); err != ErrTOTPChallengeInvalid {
			t.Fatalf("expected ErrTOTPChallengeInvalid for an orphaned challenge, got %v", err)
		}
	})

	t.Run("accounts table dropped after the challenge was issued", func(t *testing.T) {
		auth, totp, dbPath, now := newFileBackedTOTPServices(t)
		ctx := context.Background()
		_, challengeID, _ := enrollAndChallengeTOTP(t, auth, totp, now)

		dropTable(t, dbPath, "accounts")

		_, err := totp.VerifyChallenge(ctx, challengeID, "000000")
		if err == nil || errors.Is(err, ErrTOTPChallengeInvalid) {
			t.Fatalf("expected a store-failure error, not ErrTOTPChallengeInvalid, got %v", err)
		}
	})
}

// TestVerifyChallengeRejectsStaleChallengeAfterTOTPDisabledElsewhere covers
// the documented "2FA was disabled between Login and this call" edge case
// (see the comment on VerifyChallenge itself): the challenge row is set up
// normally through Login, then TOTP is cleared directly through the
// repository — bypassing Disable, which would also delete the challenge —
// to construct exactly the precondition the code comment describes.
func TestVerifyChallengeRejectsStaleChallengeAfterTOTPDisabledElsewhere(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, challengeID, secret := enrollAndChallengeTOTP(t, auth, totp, now)

	if err := totp.store.UpdateTOTPSecretAndEnabled(ctx, accountID, "", false); err != nil {
		t.Fatalf("clear totp directly through the repository: %v", err)
	}

	step := now.UTC().Unix() / security.TOTPStepSeconds
	code := security.GenerateTOTPCode(secret, step)
	if _, err := totp.VerifyChallenge(ctx, challengeID, code); err != ErrTOTPChallengeInvalid {
		t.Fatalf("expected ErrTOTPChallengeInvalid for a challenge stale because TOTP was disabled, got %v", err)
	}
}

// TestVerifyChallengeSurfacesDecryptFieldError mirrors
// TestDisableSurfacesDecryptFieldError for the login-challenge path: the
// stored secret is corrupted directly through the repository (not valid
// base64), then a real, non-expired, non-stale challenge is verified
// against it.
func TestVerifyChallengeSurfacesDecryptFieldError(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, challengeID, _ := enrollAndChallengeTOTP(t, auth, totp, now)

	if err := totp.store.UpdateTOTPSecretAndEnabled(ctx, accountID, "not valid base64!!", true); err != nil {
		t.Fatalf("corrupt totp secret: %v", err)
	}

	_, err := totp.VerifyChallenge(ctx, challengeID, "000000")
	if !errors.Is(err, ErrTOTPSecretDecrypt) {
		t.Fatalf("expected ErrTOTPSecretDecrypt for a corrupted secret, got %v", err)
	}
}

// TestVerifyChallengeSurfacesFailedAttemptsStoreError exercises
// IncrementTOTPChallengeFailedAttempts' generic-error branch: dropping
// totp_challenges.failed_attempts leaves the challenge lookup (which never
// selects that column) working, so a wrong code reaches the increment step
// and fails there.
func TestVerifyChallengeSurfacesFailedAttemptsStoreError(t *testing.T) {
	auth, totp, dbPath, now := newFileBackedTOTPServices(t)
	ctx := context.Background()
	_, challengeID, secret := enrollAndChallengeTOTP(t, auth, totp, now)

	dropTOTPChallengesFailedAttemptsColumn(t, dbPath)

	step := now.UTC().Unix() / security.TOTPStepSeconds
	wrongCode := security.GenerateTOTPCode(secret, step+50)
	_, err := totp.VerifyChallenge(ctx, challengeID, wrongCode)
	if err == nil || errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("expected a store-failure error, not ErrTOTPInvalidCode, got %v", err)
	}
	if !strings.Contains(err.Error(), "increment totp challenge attempts") {
		t.Fatalf("expected the failed-attempts store error to surface, got %v", err)
	}
}
