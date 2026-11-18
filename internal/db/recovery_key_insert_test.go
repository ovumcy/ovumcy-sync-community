package db

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestInsertRecoveryKeyPackageForSessionNeverReplaces(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	seedFaultInjectionAccount(t, store, "account-target")
	seedChangePasswordSession(t, store, "account-target", "caller")

	for _, tc := range []struct {
		name, accountID, tokenHash string
		want                       error
	}{
		{"revoked session", "account-target", "revoked", ErrSessionRevoked},
		{"missing account", "missing", "caller", ErrNotFound},
	} {
		if _, err := store.InsertRecoveryKeyPackageForSession(ctx, stepUpTestPackage(tc.accountID), tc.tokenHash); !errors.Is(err, tc.want) {
			t.Fatalf("%s: expected %v, got %v", tc.name, tc.want, err)
		}
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, "account-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused insert must not write, got %v", err)
	}

	first := stepUpTestPackage("account-target")
	if _, err := store.InsertRecoveryKeyPackageForSession(ctx, first, "caller"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	second := stepUpTestPackage("account-target")
	second.PhraseFingerprintHex = strings.Repeat("d", 16)
	if _, err := store.InsertRecoveryKeyPackageForSession(ctx, second, "caller"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second insert: expected ErrConflict, got %v", err)
	}
	if loaded, err := store.GetRecoveryKeyPackage(ctx, "account-target"); err != nil || loaded.PhraseFingerprintHex != first.PhraseFingerprintHex {
		t.Fatalf("expected the first package kept, got %#v / %v", loaded, err)
	}
}

func TestInsertRecoveryKeyPackageForSessionSurfacesStoreFailures(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		_, err := store.InsertRecoveryKeyPackageForSession(context.Background(), stepUpTestPackage("a"), "caller")
		if err == nil || !strings.Contains(err.Error(), "begin insert recovery key package") {
			t.Fatalf("expected a begin error, got %v", err)
		}
	})

	for _, tc := range []struct{ table, want string }{
		{"sessions", "session lookup"},
		{"recovery_key_packages", "insert recovery key package"},
	} {
		t.Run(tc.table+" table dropped", func(t *testing.T) {
			store, dbPath := newFileBackedTestStore(t)
			seedFaultInjectionAccount(t, store, "account-target")
			seedChangePasswordSession(t, store, "account-target", "caller")
			dropTable(t, dbPath, tc.table)

			_, err := store.InsertRecoveryKeyPackageForSession(context.Background(), stepUpTestPackage("account-target"), "caller")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}
