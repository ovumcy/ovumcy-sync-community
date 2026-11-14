package db

import (
	"context"
	"errors"
	"testing"
)

// A recovery-code rotation verified against one credential state must refuse
// once any part of it moved: a stale regenerate racing the owner's reset (new
// password and code), another regenerate (new code), or a TOTP enrollment.
func TestUpdateAccountRecoveryCodeHashRequiresVerifiedSnapshot(t *testing.T) {
	ctx := context.Background()
	verified := CredentialSnapshot{PasswordHash: "hash", RecoveryCodeHash: "code-hash"}

	cases := map[string]func(t *testing.T, store *Store){
		"password moved": func(t *testing.T, store *Store) {
			if err := store.UpdateAccountPasswordHash(ctx, "account-target", "reset-hash"); err != nil {
				t.Fatalf("move password: %v", err)
			}
		},
		"recovery code moved": func(t *testing.T, store *Store) {
			if err := store.UpdateAccountRecoveryCodeHash(ctx, "account-target", verified, "other-code-hash"); err != nil {
				t.Fatalf("move recovery code: %v", err)
			}
		},
		"totp enabled": func(t *testing.T, store *Store) {
			if err := store.UpdateTOTPSecretAndEnabled(ctx, "account-target", "secret-ciphertext", true); err != nil {
				t.Fatalf("enable totp: %v", err)
			}
		},
	}
	for name, move := range cases {
		t.Run(name, func(t *testing.T) {
			store := openTestStore(t)
			seedFaultInjectionAccount(t, store, "account-target")
			if err := store.UpdateAccountRecoveryCodeHash(ctx, "account-target", CredentialSnapshot{PasswordHash: "hash"}, "code-hash"); err != nil {
				t.Fatalf("seed recovery code: %v", err)
			}
			move(t, store)
			before, err := store.FindAccountByID(ctx, "account-target")
			if err != nil {
				t.Fatalf("load account: %v", err)
			}

			if err := store.UpdateAccountRecoveryCodeHash(ctx, "account-target", verified, "stale-code-hash"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected ErrNotFound for a stale snapshot, got %v", err)
			}
			after, err := store.FindAccountByID(ctx, "account-target")
			if err != nil {
				t.Fatalf("reload account: %v", err)
			}
			if after.RecoveryCodeHash != before.RecoveryCodeHash {
				t.Fatal("a stale rotation overwrote the recovery code")
			}
		})
	}
}
