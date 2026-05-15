package services

import (
	"context"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

func TestRegisterIssuesRecoveryCode(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	result, err := service.Register(context.Background(), "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.RecoveryCode == "" {
		t.Fatal("expected register to return a recovery code")
	}
	if len(result.RecoveryCode) < 16 {
		t.Fatalf("recovery code looks too short: %q", result.RecoveryCode)
	}
}

func TestForgotPasswordIssuesResetToken(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	if forgot.ResetToken == "" {
		t.Fatal("expected reset token")
	}
	if !forgot.ResetTokenExpiresAt.After(time.Now().UTC().Add(PasswordResetTokenTTL - time.Minute)) {
		t.Fatalf("unexpected token expiry: %v", forgot.ResetTokenExpiresAt)
	}
}

func TestForgotPasswordReplacesExistingResetToken(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	first, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode)
	if err != nil {
		t.Fatalf("first forgot: %v", err)
	}
	second, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode)
	if err != nil {
		t.Fatalf("second forgot: %v", err)
	}
	if first.ResetToken == second.ResetToken {
		t.Fatal("expected newly issued reset token to differ from prior one")
	}

	if _, err := service.ResetPassword(ctx, first.ResetToken, "fresh password value"); err != ErrInvalidResetToken {
		t.Fatalf("expected old reset token to be invalidated, got %v", err)
	}
}

func TestForgotPasswordRejectsUnknownLogin(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	_, err := service.ForgotPassword(context.Background(), "ghost@example.com", "deadbeefdeadbeefdeadbeefdeadbeef")
	if err != ErrInvalidRecoveryCredentials {
		t.Fatalf("expected ErrInvalidRecoveryCredentials, got %v", err)
	}
}

func TestForgotPasswordRejectsWrongRecoveryCode(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	if _, err := service.Register(ctx, "owner@example.com", "correct horse battery staple"); err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err := service.ForgotPassword(ctx, "owner@example.com", "00000000000000000000000000000000")
	if err != ErrInvalidRecoveryCredentials {
		t.Fatalf("expected ErrInvalidRecoveryCredentials, got %v", err)
	}
}

func TestResetPasswordRotatesPasswordRecoveryAndSessions(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	originalRecovery := registerResult.RecoveryCode

	forgot, err := service.ForgotPassword(ctx, "owner@example.com", originalRecovery)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	resetResult, err := service.ResetPassword(ctx, forgot.ResetToken, "another secure password!")
	if err != nil {
		t.Fatalf("reset password: %v", err)
	}
	if resetResult.RecoveryCode == "" || resetResult.RecoveryCode == originalRecovery {
		t.Fatalf("expected rotated recovery code, got %q (was %q)", resetResult.RecoveryCode, originalRecovery)
	}

	if _, err := service.Authenticate(ctx, registerResult.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected pre-reset session to be revoked, got %v", err)
	}

	if _, err := service.Login(ctx, "owner@example.com", "correct horse battery staple"); err != ErrInvalidCredentials {
		t.Fatalf("expected old password to fail login, got %v", err)
	}

	if _, err := service.Login(ctx, "owner@example.com", "another secure password!"); err != nil {
		t.Fatalf("expected new password to log in, got %v", err)
	}

	if _, err := service.ForgotPassword(ctx, "owner@example.com", originalRecovery); err != ErrInvalidRecoveryCredentials {
		t.Fatalf("expected old recovery code to fail after rotation, got %v", err)
	}
	if _, err := service.ForgotPassword(ctx, "owner@example.com", resetResult.RecoveryCode); err != nil {
		t.Fatalf("expected new recovery code to work, got %v", err)
	}
}

func TestResetPasswordRejectsReuse(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	if _, err := service.ResetPassword(ctx, forgot.ResetToken, "another secure password!"); err != nil {
		t.Fatalf("first reset: %v", err)
	}

	if _, err := service.ResetPassword(ctx, forgot.ResetToken, "yet another password!"); err != ErrInvalidResetToken {
		t.Fatalf("expected reuse to fail, got %v", err)
	}
}

func TestResetPasswordRejectsExpiredToken(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	now := time.Date(2026, 5, 15, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	service.now = func() time.Time { return forgot.ResetTokenExpiresAt.Add(time.Second) }
	if _, err := service.ResetPassword(ctx, forgot.ResetToken, "another secure password!"); err != ErrInvalidResetToken {
		t.Fatalf("expected expired token to fail, got %v", err)
	}
}

func TestResetPasswordRejectsWeakNew(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	if _, err := service.ResetPassword(ctx, forgot.ResetToken, "short"); err != ErrWeakNewPassword {
		t.Fatalf("expected ErrWeakNewPassword, got %v", err)
	}
}

func TestChangePasswordInvalidatesPendingResetToken(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	// Caller logs back in (still has password) and rotates it.
	loginResult, err := service.Login(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := service.ChangePassword(
		ctx,
		loginResult.AccountID,
		security.HashToken(loginResult.SessionToken),
		"correct horse battery staple",
		"replacement password phrase",
	); err != nil {
		t.Fatalf("change password: %v", err)
	}

	if _, err := service.ResetPassword(ctx, forgot.ResetToken, "yet another password!"); err != ErrInvalidResetToken {
		t.Fatalf("expected pending reset token to be invalidated after change-password, got %v", err)
	}
}

func TestRegenerateRecoveryCodeRotatesCode(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	newRecovery, err := service.RegenerateRecoveryCode(ctx, registerResult.AccountID, "correct horse battery staple")
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if newRecovery == "" || newRecovery == registerResult.RecoveryCode {
		t.Fatalf("expected new recovery code, got %q (was %q)", newRecovery, registerResult.RecoveryCode)
	}

	if _, err := service.ForgotPassword(ctx, "owner@example.com", registerResult.RecoveryCode); err != ErrInvalidRecoveryCredentials {
		t.Fatalf("expected old recovery code to fail after regenerate, got %v", err)
	}
	if _, err := service.ForgotPassword(ctx, "owner@example.com", newRecovery); err != nil {
		t.Fatalf("expected new recovery code to succeed, got %v", err)
	}
}

func TestRegenerateRecoveryCodeRejectsWrongPassword(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = service.RegenerateRecoveryCode(ctx, registerResult.AccountID, "wrong password")
	if err != ErrInvalidCurrentPassword {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
}
