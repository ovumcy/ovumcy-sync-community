package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// A recovery code held from before enrollment must not survive it: a reset
// with it would clear TOTP, letting a password holder strip the second factor
// without ever presenting it. The code issued by CompleteEnrollment works.
func TestCompleteEnrollmentRotatesRecoveryCodeIssuedBeforeEnrollment(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totpService := NewTOTPService(store, authService, key, "ovumcy-sync-community-test")
	authService.AttachTOTPChallengeIssuer(totpService)

	ctx := context.Background()
	const (
		login       = "owner@example.com"
		password    = "correct horse battery staple"
		newPassword = "replacement password phrase"
	)
	registered, err := authService.Register(ctx, login, password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := authService.RegenerateRecoveryCode(ctx, registered.AccountID, StepUp{SessionTokenHash: security.HashToken(registered.SessionToken), CurrentPassword: password}, ""); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	preEnrollRecovery, err := authService.ChangePassword(ctx, registered.AccountID, security.HashToken(registered.SessionToken), password, newPassword, "")
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	pendingReset, err := authService.ForgotPassword(ctx, login, preEnrollRecovery)
	if err != nil {
		t.Fatalf("forgot password before enrollment: %v", err)
	}

	start, err := totpService.StartEnrollment(ctx, registered.AccountID, StepUp{SessionTokenHash: security.HashToken(registered.SessionToken), CurrentPassword: newPassword})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	enrolledRecovery, err := totpService.CompleteEnrollment(
		ctx,
		registered.AccountID,
		security.HashToken(registered.SessionToken),
		security.GenerateTOTPCode(secret, time.Now().UTC().Unix()/security.TOTPStepSeconds),
	)
	if err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}
	if enrolledRecovery == "" || enrolledRecovery == preEnrollRecovery {
		t.Fatalf("expected a fresh recovery code from enrollment, got %q", enrolledRecovery)
	}

	if _, err := authService.ResetPassword(ctx, pendingReset.ResetToken, "attacker chosen password"); !errors.Is(err, ErrInvalidResetToken) {
		t.Fatalf("expected a reset token issued before enrollment to be dead, got %v", err)
	}
	if _, err := authService.ForgotPassword(ctx, login, preEnrollRecovery); !errors.Is(err, ErrInvalidRecoveryCredentials) {
		t.Fatalf("expected the pre-enrollment recovery code to fail, got %v", err)
	}
	account, err := store.FindAccountByID(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if !account.TOTPEnabled {
		t.Fatal("expected TOTP to stay enabled")
	}
	if _, err := authService.Authenticate(ctx, registered.SessionToken); err != nil {
		t.Fatalf("expected the enrolling session to survive, got %v", err)
	}

	if _, err := authService.ForgotPassword(ctx, login, enrolledRecovery); err != nil {
		t.Fatalf("expected the enrollment-issued recovery code to work, got %v", err)
	}
}

func startPendingEnrollment(t *testing.T, auth *AuthService, totp *TOTPService) (accountID, sessionToken string, secret []byte) {
	t.Helper()

	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", totpWindowTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	start, err := totp.StartEnrollment(ctx, registered.AccountID, StepUp{SessionTokenHash: security.HashToken(registered.SessionToken), CurrentPassword: totpWindowTestPassword})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err = security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return registered.AccountID, registered.SessionToken, secret
}

// A verify that succeeds hands out a recovery code, so a stolen session must
// not get unlimited guesses at a pending secret: the account window caps them
// and, once spent, burns the pending secret so guessing again needs the
// password (a new StartEnrollment, which opens a fresh window).
func TestCompleteEnrollmentGuessesAreCappedAndBurnThePendingSecret(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, sessionToken, secret := startPendingEnrollment(t, auth, totp)
	sessionHash := security.HashToken(sessionToken)

	if _, err := totp.CompleteEnrollment(ctx, accountID, sessionHash, ""); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("expected an empty code to be refused, got %v", err)
	}
	// The rolling enrollment budget refuses the sixth guess of a window,
	// without burning the secret; pacing past it reaches the pending
	// secret's lifetime cap.
	guess := 0
	for window := range maxPendingEnrollmentAttempts / maxTOTPAttempts {
		at := now.Add(time.Duration(window) * (TOTPAttemptWindow + time.Minute))
		totp.now = func() time.Time { return at }
		wrong := wrongTOTPCode(t, secret, at)
		for range maxTOTPAttempts {
			guess++
			if _, err := totp.CompleteEnrollment(ctx, accountID, sessionHash, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
				t.Fatalf("guess %d: expected ErrTOTPInvalidCode, got %v", guess, err)
			}
		}
		var locked *TOTPLockedError
		if _, err := totp.CompleteEnrollment(ctx, accountID, sessionHash, security.GenerateTOTPCode(secret, at.Unix()/security.TOTPStepSeconds)); !errors.As(err, &locked) || locked.RetryAfter <= 0 {
			t.Fatalf("window %d: expected the spent enrollment budget to refuse a correct code with a retry, got %v", window, err)
		}
	}
	paced := now.Add(time.Duration(maxPendingEnrollmentAttempts/maxTOTPAttempts) * (TOTPAttemptWindow + time.Minute))
	totp.now = func() time.Time { return paced }
	if _, err := totp.CompleteEnrollment(ctx, accountID, sessionHash, security.GenerateTOTPCode(secret, paced.Unix()/security.TOTPStepSeconds)); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected the lifetime cap to lock even a correct code after a pause, got %v", err)
	}
	totp.now = func() time.Time { return now }

	account, err := totp.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled || account.TOTPSecretEncrypted != "" {
		t.Fatalf("expected the pending secret burnt and TOTP off, got enabled=%v secret-set=%v", account.TOTPEnabled, account.TOTPSecretEncrypted != "")
	}

	start, err := totp.StartEnrollment(ctx, accountID, StepUp{SessionTokenHash: sessionHash, CurrentPassword: totpWindowTestPassword})
	if err != nil {
		t.Fatalf("restart enrollment: %v", err)
	}
	fresh, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if _, err := totp.CompleteEnrollment(ctx, accountID, sessionHash, security.GenerateTOTPCode(fresh, now.Unix()/security.TOTPStepSeconds)); err != nil {
		t.Fatalf("expected a restarted enrollment to complete, got %v", err)
	}
}

// The pending secret's lifetime count survives a clock stepped back behind
// its first guess: the attempt past the cap burns the secret even with a
// correct code. The guesses are paced so the last rolling window holds one,
// leaving the rolling budget open at the stepped-back time.
func TestPendingEnrollmentLifetimeCapSurvivesAClockStepBack(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, sessionToken, secret := startPendingEnrollment(t, auth, totp)
	sessionHash := security.HashToken(sessionToken)

	perWindow := []int{maxTOTPAttempts, maxPendingEnrollmentAttempts - maxTOTPAttempts - 1, 1}
	for window, guesses := range perWindow {
		at := now.Add(time.Duration(window) * (TOTPAttemptWindow + time.Minute))
		totp.now = func() time.Time { return at }
		wrong := wrongTOTPCode(t, secret, at)
		for range guesses {
			if _, err := totp.CompleteEnrollment(ctx, accountID, sessionHash, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
				t.Fatalf("window %d: expected ErrTOTPInvalidCode, got %v", window, err)
			}
		}
	}

	stepBack := now.Add(-time.Hour)
	totp.now = func() time.Time { return stepBack }
	var locked *TOTPLockedError
	if _, err := totp.CompleteEnrollment(ctx, accountID, sessionHash, security.GenerateTOTPCode(secret, stepBack.Unix()/security.TOTPStepSeconds)); !errors.As(err, &locked) || locked.RetryAfter != 0 {
		t.Fatalf("expected the attempt past the lifetime cap to burn the secret after a clock step back, got %v", err)
	}
	account, err := totp.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled || account.TOTPSecretEncrypted != "" {
		t.Fatalf("expected the pending secret burnt and TOTP off, got enabled=%v secret-set=%v", account.TOTPEnabled, account.TOTPSecretEncrypted != "")
	}
}

// A failed reservation stops the verify before the code is looked at, and
// changes nothing.
func TestCompleteEnrollmentSurfacesReservationStoreError(t *testing.T) {
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
	accountID, sessionToken, secret := startPendingEnrollment(t, auth, totp)

	dropTable(t, dbPath, "totp_failure_windows")

	code := security.GenerateTOTPCode(secret, now.Unix()/security.TOTPStepSeconds)
	if _, err := totp.CompleteEnrollment(ctx, accountID, security.HashToken(sessionToken), code); err == nil || errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("expected the reservation store error to surface, got %v", err)
	}
	account, err := store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled || account.TOTPSecretEncrypted == "" {
		t.Fatalf("expected the pending enrollment untouched, got enabled=%v secret-set=%v", account.TOTPEnabled, account.TOTPSecretEncrypted != "")
	}
}

// A StartEnrollment that lands between the code check and the enable swaps in
// a secret nobody verified; the step claim, bound to the verified secret,
// refuses it before the enable could turn it on.
func TestCompleteEnrollmentRefusesASecretReplacedMidVerify(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, sessionToken, secret := startPendingEnrollment(t, auth, totp)

	restarted := false
	totp.now = func() time.Time {
		if !restarted {
			restarted = true
			if _, err := totp.StartEnrollment(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}); err != nil {
				t.Fatalf("concurrent StartEnrollment: %v", err)
			}
		}
		return now
	}

	code := security.GenerateTOTPCode(secret, now.Unix()/security.TOTPStepSeconds)
	if _, err := totp.CompleteEnrollment(ctx, accountID, security.HashToken(sessionToken), code); !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected ErrTOTPReplayed for a replaced pending secret, got %v", err)
	}
	account, err := totp.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled {
		t.Fatal("expected the unverified replacement secret to stay disabled")
	}
}

// A concurrent verify that enabled first wins; the loser hands out no code.
func TestCompleteEnrollmentLosesToAConcurrentEnable(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, sessionToken, secret := startPendingEnrollment(t, auth, totp)

	enabled := false
	totp.now = func() time.Time {
		if !enabled {
			enabled = true
			account, err := totp.store.FindAccountByID(ctx, accountID)
			if err != nil {
				t.Fatalf("find account: %v", err)
			}
			if err := totp.store.EnableTOTPAndRotateRecoveryCode(ctx, accountID, account.TOTPSecretEncrypted, "winner-recovery-hash", security.HashToken(sessionToken)); err != nil {
				t.Fatalf("concurrent enable: %v", err)
			}
		}
		return now
	}

	code := security.GenerateTOTPCode(secret, now.Unix()/security.TOTPStepSeconds)
	if _, err := totp.CompleteEnrollment(ctx, accountID, security.HashToken(sessionToken), code); !errors.Is(err, ErrTOTPAlreadyEnabled) {
		t.Fatalf("expected ErrTOTPAlreadyEnabled for the losing verify, got %v", err)
	}
	account, err := totp.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.RecoveryCodeHash != "winner-recovery-hash" {
		t.Fatal("expected the winner's recovery code to stand")
	}
}
