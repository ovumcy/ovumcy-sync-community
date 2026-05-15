package services

import (
	"context"
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

	if err := service.ChangePassword(
		ctx,
		first.AccountID,
		security.HashToken(first.SessionToken),
		"correct horse battery staple",
		"new staple battery horse correct",
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

func TestChangePasswordRejectsWrongCurrent(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	result, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	err = service.ChangePassword(
		ctx,
		result.AccountID,
		security.HashToken(result.SessionToken),
		"wrong current password",
		"new staple battery horse correct",
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

	err = service.ChangePassword(
		ctx,
		result.AccountID,
		security.HashToken(result.SessionToken),
		"correct horse battery staple",
		"correct horse battery staple",
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

	err = service.ChangePassword(
		ctx,
		result.AccountID,
		security.HashToken(result.SessionToken),
		"correct horse battery staple",
		"short",
	)
	if err != ErrWeakNewPassword {
		t.Fatalf("expected ErrWeakNewPassword, got %v", err)
	}
}

func TestChangePasswordUnknownAccountIsUnauthorized(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	err := service.ChangePassword(
		context.Background(),
		"missing-account",
		security.HashToken("any"),
		"correct horse battery staple",
		"new staple battery horse correct",
	)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}
