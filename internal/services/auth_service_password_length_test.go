package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// overlongPassword is 37 Cyrillic runes = 74 UTF-8 bytes: valid by the rune
// minimum, over bcrypt's 72-byte ceiling.
var overlongPassword = strings.Repeat("ж", 37)

const lengthTestPassword = "correct horse battery staple"

func TestRegisterRejectsPasswordOverByteLimit(t *testing.T) {
	service := NewAuthService(openTestStore(t), 24*time.Hour)

	_, err := service.Register(context.Background(), "owner@example.com", overlongPassword)
	if err != ErrInvalidRegistrationInput {
		t.Fatalf("expected ErrInvalidRegistrationInput, got %v", err)
	}
}

func TestChangePasswordRejectsNewPasswordOverByteLimit(t *testing.T) {
	service := NewAuthService(openTestStore(t), 24*time.Hour)
	ctx := context.Background()

	registered, err := service.Register(ctx, "owner@example.com", lengthTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	err = service.ChangePassword(ctx, registered.AccountID, security.HashToken(registered.SessionToken), lengthTestPassword, overlongPassword)
	if err != ErrWeakNewPassword {
		t.Fatalf("expected ErrWeakNewPassword, got %v", err)
	}
	if _, err := service.Login(ctx, "owner@example.com", lengthTestPassword); err != nil {
		t.Fatalf("expected the old password to still log in, got %v", err)
	}
}

// TestResetPasswordRejectedPasswordKeepsToken pins that a weak or over-long
// new password is refused before the single-use reset token is consumed, so
// the owner can retry with a corrected password.
func TestResetPasswordRejectedPasswordKeepsToken(t *testing.T) {
	service := NewAuthService(openTestStore(t), 24*time.Hour)
	ctx := context.Background()

	registered, err := service.Register(ctx, "owner@example.com", lengthTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registered.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	for _, rejected := range []string{overlongPassword, "short"} {
		if _, err := service.ResetPassword(ctx, forgot.ResetToken, rejected); err != ErrWeakNewPassword {
			t.Fatalf("expected ErrWeakNewPassword for %q, got %v", rejected, err)
		}
	}

	if _, err := service.ResetPassword(ctx, forgot.ResetToken, "a brand new password"); err != nil {
		t.Fatalf("expected the reset token to survive rejected attempts, got %v", err)
	}
}
