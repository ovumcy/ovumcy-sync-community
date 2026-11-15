package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

func TestChangePasswordSuccessRevokesOtherSessions(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	first, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	second, err := service.Login(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("second login: %v", err)
	}

	if _, err := service.ChangePassword(
		ctx,
		first.AccountID,
		security.HashToken(first.SessionToken),
		"correct horse battery staple",
		"new staple battery horse correct",
		"",
	); err != nil {
		t.Fatalf("change password: %v", err)
	}

	if _, err := service.Authenticate(ctx, first.SessionToken); err != nil {
		t.Fatalf("expected current session to remain valid, got %v", err)
	}

	if _, err := service.Authenticate(ctx, second.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected other session to be revoked, got %v", err)
	}

	if _, err := service.Login(ctx, "owner@example.com", "correct horse battery staple"); err != ErrInvalidCredentials {
		t.Fatalf("expected old password to fail login, got %v", err)
	}

	if _, err := service.Login(ctx, "owner@example.com", "new staple battery horse correct"); err != nil {
		t.Fatalf("expected new password to succeed, got %v", err)
	}
}

// The change hands out a fresh recovery code and retires the old one.
func TestChangePasswordRotatesRecoveryCode(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registered, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	newRecovery, err := service.ChangePassword(
		ctx,
		registered.AccountID,
		security.HashToken(registered.SessionToken),
		"correct horse battery staple",
		"new staple battery horse correct",
		"",
	)
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	if newRecovery == "" || newRecovery == registered.RecoveryCode {
		t.Fatalf("expected a new recovery code, got %q", newRecovery)
	}
	if _, err := service.ForgotPassword(ctx, "owner@example.com", registered.RecoveryCode); !errors.Is(err, ErrInvalidRecoveryCredentials) {
		t.Fatalf("expected the old recovery code refused, got %v", err)
	}
	if _, err := service.ForgotPassword(ctx, "owner@example.com", newRecovery); err != nil {
		t.Fatalf("expected the new recovery code to work: %v", err)
	}
}

// On an enrolled account the password alone must not rotate the recovery
// code: a reset with it clears TOTP.
func TestChangePasswordOnTOTPAccountRequiresCode(t *testing.T) {
	const password = "correct horse battery staple"
	auth, totp, now := fixedTOTPClock(t)
	accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)
	ctx := context.Background()
	sessionHash := security.HashToken(token)
	enrolled, err := auth.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}

	for _, code := range []string{"", "000000"} {
		if _, err := auth.ChangePassword(ctx, accountID, sessionHash, password, "new staple battery horse correct", code); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("code %q: expected ErrTOTPInvalidCode, got %v", code, err)
		}
	}
	account, err := auth.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.RecoveryCodeHash != enrolled.RecoveryCodeHash || account.PasswordHash != enrolled.PasswordHash {
		t.Fatal("a refused change must leave the password and recovery code untouched")
	}

	later := now.Add(security.TOTPStepSeconds * time.Second)
	totp.now = func() time.Time { return later }
	code := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	newRecovery, err := auth.ChangePassword(ctx, accountID, sessionHash, password, "new staple battery horse correct", code)
	if err != nil {
		t.Fatalf("change with a current code: %v", err)
	}
	if _, err := auth.ForgotPassword(ctx, "owner@example.com", newRecovery); err != nil {
		t.Fatalf("expected the new recovery code to work: %v", err)
	}
	account, err = auth.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.RecoveryCodeHash == enrolled.RecoveryCodeHash {
		t.Fatal("expected the enrollment recovery code replaced")
	}
}

// A weak new password is refused before the code is checked, so the code's
// step stays usable.
func TestChangePasswordOnTOTPAccountValidatesPasswordBeforeCode(t *testing.T) {
	const password = "correct horse battery staple"
	auth, totp, now := fixedTOTPClock(t)
	accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)
	ctx := context.Background()
	later := now.Add(security.TOTPStepSeconds * time.Second)
	totp.now = func() time.Time { return later }
	code := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)

	if _, err := auth.ChangePassword(ctx, accountID, security.HashToken(token), password, "short", code); !errors.Is(err, ErrWeakNewPassword) {
		t.Fatalf("expected ErrWeakNewPassword, got %v", err)
	}
	if _, err := auth.ChangePassword(ctx, accountID, security.HashToken(token), password, "new staple battery horse correct", code); err != nil {
		t.Fatalf("the code must still be usable after a weak-password attempt: %v", err)
	}
}

func TestChangePasswordOnTOTPAccountFailsClosedWithoutVerifier(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, token, _, _ := enrollTOTP(t, auth, totp, now)
	unwired := NewAuthService(auth.store, 24*time.Hour)

	if _, err := unwired.ChangePassword(context.Background(), accountID, security.HashToken(token), "correct horse battery staple", "new staple battery horse correct", "123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("expected ErrTOTPNotConfigured, got %v", err)
	}
}

func TestChangePasswordRejectsWrongCurrent(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	result, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = service.ChangePassword(
		ctx,
		result.AccountID,
		security.HashToken(result.SessionToken),
		"wrong current password",
		"new staple battery horse correct",
		"",
	)
	if err != ErrInvalidCurrentPassword {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}

	if _, err := service.Authenticate(ctx, result.SessionToken); err != nil {
		t.Fatalf("expected session to remain valid after failed change, got %v", err)
	}
}

func TestChangePasswordRejectsSamePassword(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	result, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = service.ChangePassword(
		ctx,
		result.AccountID,
		security.HashToken(result.SessionToken),
		"correct horse battery staple",
		"correct horse battery staple",
		"",
	)
	if err != ErrNewPasswordMustDiffer {
		t.Fatalf("expected ErrNewPasswordMustDiffer, got %v", err)
	}
}

func TestChangePasswordRejectsWeakNew(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	result, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = service.ChangePassword(
		ctx,
		result.AccountID,
		security.HashToken(result.SessionToken),
		"correct horse battery staple",
		"short",
		"",
	)
	if err != ErrWeakNewPassword {
		t.Fatalf("expected ErrWeakNewPassword, got %v", err)
	}
}

func TestChangePasswordUnknownAccountIsUnauthorized(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	_, err := service.ChangePassword(
		context.Background(),
		"missing-account",
		security.HashToken("any"),
		"correct horse battery staple",
		"new staple battery horse correct",
		"",
	)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}
