package services

import (
	"context"
	"errors"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// A secret started under the old password must not survive a password change:
// enrollment completion needs only a session, so a later session could
// otherwise enable TOTP with the planted secret and take the recovery code.
func TestChangePasswordDiscardsAPendingEnrollment(t *testing.T) {
	const (
		password    = "correct horse battery staple"
		newPassword = "new staple battery horse correct"
	)
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()

	owner, err := auth.Register(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	planter, err := auth.Login(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("planter login: %v", err)
	}
	start, err := totp.StartEnrollment(ctx, owner.AccountID, StepUp{SessionTokenHash: security.HashToken(planter.SessionToken), CurrentPassword: password})
	if err != nil {
		t.Fatalf("start enrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	if _, err := auth.ChangePassword(ctx, owner.AccountID, security.HashToken(owner.SessionToken), password, newPassword, ""); err != nil {
		t.Fatalf("change password: %v", err)
	}

	later, err := auth.Login(ctx, "owner@example.com", newPassword)
	if err != nil {
		t.Fatalf("later login: %v", err)
	}
	code := security.GenerateTOTPCode(secret, now.Unix()/security.TOTPStepSeconds)
	if _, err := totp.CompleteEnrollment(ctx, owner.AccountID, security.HashToken(later.SessionToken), code); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("expected the planted secret gone (ErrTOTPNotConfigured), got %v", err)
	}
	account, err := auth.store.FindAccountByID(ctx, owner.AccountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled {
		t.Fatal("expected TOTP to stay off")
	}
}
