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
	preEnrollRecovery, err := authService.RegenerateRecoveryCode(ctx, registered.AccountID, password, "")
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if err := authService.ChangePassword(ctx, registered.AccountID, security.HashToken(registered.SessionToken), password, newPassword); err != nil {
		t.Fatalf("change password: %v", err)
	}
	pendingReset, err := authService.ForgotPassword(ctx, login, preEnrollRecovery)
	if err != nil {
		t.Fatalf("forgot password before enrollment: %v", err)
	}

	start, err := totpService.StartEnrollment(ctx, registered.AccountID, newPassword)
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
