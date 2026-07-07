package services

import (
	"context"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// fixedTOTPClock pins both the auth and TOTP services to the same instant so
// that enrollment verification, the login challenge, and disable all resolve
// to a single, known TOTP step. That determinism is what lets these tests
// replay the exact same code without racing a real 30-second step boundary.
func fixedTOTPClock(t *testing.T) (auth *AuthService, totp *TOTPService, now time.Time) {
	t.Helper()

	store := openTestStore(t)
	auth = NewAuthService(store, 24*time.Hour)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp = NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)

	// A step boundary would let a code that is valid "now" fall out of the
	// window between two service calls. Anchor a few seconds into a step so
	// the whole test observes one stable step.
	now = time.Date(2026, 7, 7, 10, 0, 5, 0, time.UTC)
	auth.now = func() time.Time { return now }
	totp.now = func() time.Time { return now }
	return auth, totp, now
}

// enrollTOTP registers an account and completes TOTP enrollment at the pinned
// clock's step, returning the account id, the enrollment session token, the
// decoded secret, and the code (== step) that was consumed by CompleteEnrollment.
func enrollTOTP(
	t *testing.T,
	auth *AuthService,
	totp *TOTPService,
	now time.Time,
) (accountID, sessionToken string, secret []byte, enrollCode string) {
	t.Helper()

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
	secret, err = security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	step := now.UTC().Unix() / security.TOTPStepSeconds
	enrollCode = security.GenerateTOTPCode(secret, step)
	if err := totp.CompleteEnrollment(
		ctx,
		registered.AccountID,
		security.HashToken(registered.SessionToken),
		enrollCode,
	); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	return registered.AccountID, registered.SessionToken, secret, enrollCode
}

// TestCompleteEnrollmentStepSurvivesEnableSoLoginChallengeCannotReplay is the
// direct regression for the replayable-enrollment-code bug (#33): the enable
// transition used to reset totp_last_used_step to 0, so the code just consumed
// by CompleteEnrollment was accepted a second time by the login challenge path
// within its skew window. With the step preserved across enable, the login
// challenge must reject the same code as a replay.
func TestCompleteEnrollmentStepSurvivesEnableSoLoginChallengeCannotReplay(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	_, _, _, enrollCode := enrollTOTP(t, auth, totp, now)

	// Password login on the 2FA account returns a challenge, not a session.
	loginResult, err := auth.Login(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loginResult.TOTPChallenge == nil || loginResult.TOTPChallenge.ChallengeID == "" {
		t.Fatalf("expected a TOTP challenge, got %#v", loginResult)
	}
	if loginResult.SessionToken != "" {
		t.Fatalf("expected no session token alongside challenge, got %q", loginResult.SessionToken)
	}

	// Same code, same (pinned) step: must be rejected as a replay, not minted
	// into a session.
	_, err = totp.VerifyChallenge(ctx, loginResult.TOTPChallenge.ChallengeID, enrollCode)
	if err != ErrTOTPReplayed {
		t.Fatalf("expected ErrTOTPReplayed for reused enrollment code, got %v", err)
	}
}

// TestCompleteEnrollmentStepSurvivesEnableSoDisableCannotReplay is the second
// half of #33: disable also verifies a TOTP code and claims its step, so the
// erased-step bug let the just-used enrollment code satisfy disable within its
// window. With the step preserved, disable must reject the reused code.
func TestCompleteEnrollmentStepSurvivesEnableSoDisableCannotReplay(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	accountID, _, _, enrollCode := enrollTOTP(t, auth, totp, now)

	if err := totp.Disable(ctx, accountID, password, enrollCode); err != ErrTOTPReplayed {
		t.Fatalf("expected ErrTOTPReplayed for reused enrollment code on disable, got %v", err)
	}

	// The account must still be enrolled: a rejected disable cannot have torn
	// down the second factor.
	account, err := totp.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("FindAccountByID: %v", err)
	}
	if !account.TOTPEnabled {
		t.Fatal("expected TOTP to remain enabled after a replayed disable code")
	}
	if account.TOTPSecretEncrypted == "" {
		t.Fatal("expected TOTP secret to remain after a replayed disable code")
	}
}

// TestFreshStartEnrollmentResetsStaleStepClaim guards the counterpart property:
// StartEnrollment stores a brand-new secret and MUST reset totp_last_used_step,
// so a high step left over from an earlier enrollment/claim does not reject the
// new secret's first valid code inside the same skew window.
func TestFreshStartEnrollmentResetsStaleStepClaim(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	// First enrollment claims the current step at the pinned clock.
	accountID, sessionToken, _, _ := enrollTOTP(t, auth, totp, now)

	// Owner disables (clears the secret) so we can re-enroll. Use a fresh step
	// so disable itself is not a replay of the enrollment step.
	disableNow := now.Add(2 * security.TOTPStepSeconds * time.Second)
	auth.now = func() time.Time { return disableNow }
	totp.now = func() time.Time { return disableNow }

	account, err := totp.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("FindAccountByID: %v", err)
	}
	secret, err := security.DecryptField(
		account.TOTPSecretEncrypted,
		totp.secretKey,
		aadForTOTPSecret(accountID),
	)
	if err != nil {
		t.Fatalf("decrypt secret: %v", err)
	}
	disableStep := disableNow.UTC().Unix() / security.TOTPStepSeconds
	if err := totp.Disable(
		ctx,
		accountID,
		password,
		security.GenerateTOTPCode([]byte(secret), disableStep),
	); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	_ = sessionToken

	// Re-enroll at a step EARLIER than the one the first enrollment claimed, to
	// prove the stale high claim was reset by StartEnrollment. Without the
	// reset, ClaimTOTPStep(earlierStep) would fail because the persisted step
	// is still the (higher) disable step, and this verify would wrongly report
	// a replay.
	reEnrollNow := now // back to the original, lower step
	auth.now = func() time.Time { return reEnrollNow }
	totp.now = func() time.Time { return reEnrollNow }

	start, err := totp.StartEnrollment(ctx, accountID, password)
	if err != nil {
		t.Fatalf("second StartEnrollment: %v", err)
	}
	newSecret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode new secret: %v", err)
	}
	reEnrollStep := reEnrollNow.UTC().Unix() / security.TOTPStepSeconds
	if err := totp.CompleteEnrollment(
		ctx,
		accountID,
		security.HashToken(sessionToken),
		security.GenerateTOTPCode(newSecret, reEnrollStep),
	); err != nil {
		t.Fatalf("second CompleteEnrollment should accept the first code of a fresh secret, got %v", err)
	}
}

// TestLoginChallengeSucceedsOnAFreshStep is the positive counterpart to the
// replay tests: once the clock advances past the enrollment step, a valid code
// for the new step completes the login challenge and mints a session. This
// keeps the step-preservation fix from silently over-blocking legitimate logins.
func TestLoginChallengeSucceedsOnAFreshStep(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"

	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	// Advance one full step past enrollment so a new code is available.
	loginNow := now.Add(security.TOTPStepSeconds * time.Second)
	auth.now = func() time.Time { return loginNow }
	totp.now = func() time.Time { return loginNow }

	loginResult, err := auth.Login(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loginResult.TOTPChallenge == nil {
		t.Fatalf("expected a TOTP challenge, got %#v", loginResult)
	}

	loginStep := loginNow.UTC().Unix() / security.TOTPStepSeconds
	authResult, err := totp.VerifyChallenge(
		ctx,
		loginResult.TOTPChallenge.ChallengeID,
		security.GenerateTOTPCode(secret, loginStep),
	)
	if err != nil {
		t.Fatalf("VerifyChallenge on a fresh step: %v", err)
	}
	if authResult.SessionToken == "" {
		t.Fatal("expected a session token from a completed challenge")
	}
	if authResult.AccountID != accountID {
		t.Fatalf("session issued for wrong account: got %q want %q", authResult.AccountID, accountID)
	}
}
