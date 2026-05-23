package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

func TestResetPasswordClearsTOTPAndPendingChallenges(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totpService := NewTOTPService(store, authService, key, "ovumcy-sync-community-test")
	authService.AttachTOTPChallengeIssuer(totpService)

	ctx := context.Background()
	registered, err := authService.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Enable TOTP.
	start, err := totpService.StartEnrollment(ctx, registered.AccountID, "correct horse battery staple")
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	enrollStep := time.Now().UTC().Unix() / security.TOTPStepSeconds
	if err := totpService.CompleteEnrollment(
		ctx,
		registered.AccountID,
		security.HashToken(registered.SessionToken),
		security.GenerateTOTPCode(secret, enrollStep),
	); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	// Mint a pending login challenge that should be wiped by reset.
	if _, _, err := totpService.IssueChallenge(ctx, registered.AccountID); err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// Use the recovery code to reset.
	forgot, err := authService.ForgotPassword(ctx, "owner@example.com", registered.RecoveryCode)
	if err != nil {
		t.Fatalf("ForgotPassword: %v", err)
	}
	if _, err := authService.ResetPassword(ctx, forgot.ResetToken, "fresh secret password!"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Stored account no longer has TOTP enabled.
	account, err := store.FindAccountByID(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("FindAccountByID: %v", err)
	}
	if account.TOTPEnabled {
		t.Fatal("expected TOTP to be disabled after recovery reset")
	}
	if account.TOTPSecretEncrypted != "" {
		t.Fatalf("expected empty TOTP secret, got %q", account.TOTPSecretEncrypted)
	}

	// Login with the new password is regular (no challenge).
	loginResult, err := authService.Login(ctx, "owner@example.com", "fresh secret password!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loginResult.SessionToken == "" {
		t.Fatal("expected session token, got empty")
	}
	if loginResult.TOTPChallenge != nil {
		t.Fatal("expected no TOTP challenge after recovery reset")
	}
}

// TestResetPasswordConcurrentReuseRejectsAllButOne is the regression for
// HIGH-1: see the matching test in ovumcy-managed. Before the consumed_at
// CAS, N concurrent POST /auth/reset-password with the same plaintext token
// could all succeed and return N divergent recovery codes. The atomic
// UPDATE ... SET consumed_at=? WHERE consumed_at IS NULL must collapse that
// to exactly one winner regardless of fanout.
func TestResetPasswordConcurrentReuseRejectsAllButOne(t *testing.T) {
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

	const fanout = 8
	results := make([]error, fanout)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < fanout; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := service.ResetPassword(ctx, forgot.ResetToken, fmt.Sprintf("rotated horse battery staple %d", i))
			results[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvalidResetToken):
		default:
			t.Errorf("unexpected error from concurrent reset: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful reset across %d concurrent attempts, got %d", fanout, successes)
	}

	if _, err := service.ResetPassword(ctx, forgot.ResetToken, "rotated horse battery staple final"); !errors.Is(err, ErrInvalidResetToken) {
		t.Fatalf("expected sequential reuse after concurrent winner to fail, got %v", err)
	}
}
