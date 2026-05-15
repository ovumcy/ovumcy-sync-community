package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// These tests guard against the account-existence timing oracle: every
// "invalid creds" or "invalid recovery credentials" early-return path in
// Login and ForgotPassword must still invoke the bcrypt equalizer so an
// attacker cannot distinguish "no such account" (~instant) or "account
// exists but no recovery code set" (~instant) from "wrong credential"
// (~bcrypt cost).
//
// We assert call counts rather than wall-clock latency so the suite stays
// deterministic on shared CI runners.

func withCountingPasswordEqualizer(t *testing.T) *int {
	t.Helper()

	original := equalizePasswordTiming
	count := 0
	equalizePasswordTiming = func(string) {
		count++
	}
	t.Cleanup(func() {
		equalizePasswordTiming = original
	})
	return &count
}

func TestLoginEqualizesTimingForUnknownLogin(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	count := withCountingPasswordEqualizer(t)

	_, err := service.Login(context.Background(), "ghost@example.com", "any password 12345")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if *count != 1 {
		t.Fatalf("expected exactly 1 timing-equalization call on unknown-login path, got %d", *count)
	}
}

func TestForgotPasswordEqualizesTimingForUnknownLogin(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	count := withCountingPasswordEqualizer(t)

	_, err := service.ForgotPassword(context.Background(), "ghost@example.com", "deadbeefdeadbeefdeadbeefdeadbeef")
	if err != ErrInvalidRecoveryCredentials {
		t.Fatalf("expected ErrInvalidRecoveryCredentials, got %v", err)
	}
	if *count != 1 {
		t.Fatalf("expected exactly 1 timing-equalization call on unknown-login path, got %d", *count)
	}
}

func TestForgotPasswordEqualizesTimingWhenRecoveryCodeUnset(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	ctx := context.Background()
	registerResult, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Wipe recovery_code_hash to simulate a pre-migration account that has
	// never had one set.
	if err := store.UpdateAccountRecoveryCodeHash(ctx, registerResult.AccountID, ""); err != nil {
		t.Fatalf("clear recovery code hash: %v", err)
	}

	count := withCountingPasswordEqualizer(t)

	_, err = service.ForgotPassword(ctx, "owner@example.com", "deadbeefdeadbeefdeadbeefdeadbeef")
	if err != ErrInvalidRecoveryCredentials {
		t.Fatalf("expected ErrInvalidRecoveryCredentials, got %v", err)
	}
	if *count != 1 {
		t.Fatalf("expected exactly 1 timing-equalization call on empty-recovery-hash path, got %d", *count)
	}
}

// TestPasswordTimingEqualizationHashIsBcryptCompatible ensures the constant
// is never silently corrupted into an unparseable value, which would make
// the equalizer return instantly and reintroduce the timing oracle.
func TestPasswordTimingEqualizationHashIsBcryptCompatible(t *testing.T) {
	err := bcrypt.CompareHashAndPassword([]byte(passwordTimingEqualizationHash), []byte("any"))
	if err == nil {
		t.Fatal("hash unexpectedly matched 'any' — wrong placeholder?")
	}
	if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("placeholder hash unparseable, equalizer would short-circuit: %v", err)
	}
}
