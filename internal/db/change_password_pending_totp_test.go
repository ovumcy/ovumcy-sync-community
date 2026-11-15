package db

import (
	"context"
	"errors"
	"testing"
)

// An enrollment start verified against a password that has since changed
// leaves no pending secret behind the change.
func TestStorePendingTOTPSecretRefusesAStaleVerifiedHash(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	seedFaultInjectionAccount(t, store, "stale-account")
	seedChangePasswordSession(t, store, "stale-account", "stale-caller")
	if err := store.ChangeAccountPassword(ctx, "stale-account", "hash", "", "new-hash", "new-recovery", "stale-caller"); err != nil {
		t.Fatalf("change password: %v", err)
	}

	if err := store.StorePendingTOTPSecret(ctx, "stale-account", "hash", "stale-caller", "late-secret"); !errors.Is(err, ErrPasswordChanged) {
		t.Fatalf("expected ErrPasswordChanged, got %v", err)
	}
	account, err := store.FindAccountByID(ctx, "stale-account")
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPSecretEncrypted != "" {
		t.Fatal("expected no pending secret written")
	}
}

// A password change clears a pending enrollment secret but leaves an enabled
// factor exactly as it was.
func TestChangeAccountPasswordClearsOnlyAPendingTOTPSecret(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)

	seedFaultInjectionAccount(t, store, "pending-account")
	seedChangePasswordSession(t, store, "pending-account", "pending-caller")
	if err := store.UpdateTOTPSecretAndEnabled(ctx, "pending-account", "pending-secret", false); err != nil {
		t.Fatalf("seed pending secret: %v", err)
	}

	seedFaultInjectionAccount(t, store, "enabled-account")
	seedChangePasswordSession(t, store, "enabled-account", "enabled-caller")
	if err := store.UpdateTOTPSecretAndEnabled(ctx, "enabled-account", "enabled-secret", true); err != nil {
		t.Fatalf("seed enabled secret: %v", err)
	}
	if claimed, err := store.ClaimTOTPStep(ctx, "enabled-account", "enabled-secret", 42); err != nil || !claimed {
		t.Fatalf("claim step: %v %v", claimed, err)
	}

	for _, tc := range []struct{ account, caller string }{
		{"pending-account", "pending-caller"},
		{"enabled-account", "enabled-caller"},
	} {
		if err := store.ChangeAccountPassword(ctx, tc.account, "hash", "", "new-hash", "new-recovery", tc.caller); err != nil {
			t.Fatalf("change %s: %v", tc.account, err)
		}
	}

	pending, err := store.FindAccountByID(ctx, "pending-account")
	if err != nil {
		t.Fatalf("find pending account: %v", err)
	}
	if pending.TOTPEnabled || pending.TOTPSecretEncrypted != "" || pending.TOTPLastUsedStep != 0 {
		t.Fatalf("expected the pending secret cleared, got enabled=%v step=%d", pending.TOTPEnabled, pending.TOTPLastUsedStep)
	}

	enabled, err := store.FindAccountByID(ctx, "enabled-account")
	if err != nil {
		t.Fatalf("find enabled account: %v", err)
	}
	if !enabled.TOTPEnabled || enabled.TOTPSecretEncrypted != "enabled-secret" || enabled.TOTPLastUsedStep != 42 {
		t.Fatalf("expected the enabled factor untouched, got enabled=%v step=%d", enabled.TOTPEnabled, enabled.TOTPLastUsedStep)
	}
}
