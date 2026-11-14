package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func stepUpTestPackage(accountID string) models.RecoveryKeyPackage {
	return models.RecoveryKeyPackage{
		AccountID:            accountID,
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: strings.Repeat("c", 16),
		UpdatedAt:            time.Now().UTC(),
	}
}

func TestStepUpWritesRefuseAStaleState(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	seedFaultInjectionAccount(t, store, "account-target")
	seedChangePasswordSession(t, store, "account-target", "caller")

	for _, tc := range []struct {
		name, accountID, verifiedHash, tokenHash string
		want                                     error
	}{
		{"moved hash", "account-target", "stale", "caller", ErrConflict},
		{"revoked session", "account-target", "hash", "revoked", ErrSessionRevoked},
		{"revoked session and moved hash", "account-target", "stale", "revoked", ErrSessionRevoked},
		{"missing account", "missing", "hash", "caller", ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.DeleteAccountForSession(ctx, tc.accountID, tc.verifiedHash, tc.tokenHash); !errors.Is(err, tc.want) {
				t.Fatalf("delete: expected %v, got %v", tc.want, err)
			}
			pkg := stepUpTestPackage(tc.accountID)
			if _, err := store.UpsertRecoveryKeyPackageForSession(ctx, pkg, tc.verifiedHash, tc.tokenHash); !errors.Is(err, tc.want) {
				t.Fatalf("upsert: expected %v, got %v", tc.want, err)
			}
		})
	}

	if _, err := store.FindAccountByID(ctx, "account-target"); err != nil {
		t.Fatalf("a refused delete must keep the account: %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, "account-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused upsert must not write, got %v", err)
	}

	stored, err := store.UpsertRecoveryKeyPackageForSession(ctx, stepUpTestPackage("account-target"), "hash", "caller")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if loaded, err := store.GetRecoveryKeyPackage(ctx, "account-target"); err != nil || loaded.WrapNonceHex != stored.WrapNonceHex {
		t.Fatalf("expected the package stored, got %#v / %v", loaded, err)
	}

	if err := store.DeleteAccountForSession(ctx, "account-target", "hash", "caller"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.FindAccountByID(ctx, "account-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the account erased, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "caller"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the caller's session erased, got %v", err)
	}
}

func TestStepUpWritesSurfaceStoreFailures(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		ctx := context.Background()
		if err := store.DeleteAccountForSession(ctx, "a", "hash", "caller"); err == nil || !strings.Contains(err.Error(), "begin delete account") {
			t.Fatalf("delete: expected a begin error, got %v", err)
		}
		if _, err := store.UpsertRecoveryKeyPackageForSession(ctx, stepUpTestPackage("a"), "hash", "caller"); err == nil || !strings.Contains(err.Error(), "begin upsert recovery key package") {
			t.Fatalf("upsert: expected a begin error, got %v", err)
		}
	})

	for _, tc := range []struct{ table, wantDelete, wantUpsert string }{
		{"sessions", "step-up state lookup", "step-up state lookup"},
		{"devices", "delete account devices rows", ""},
		{"recovery_key_packages", "delete account recovery_key_packages rows", "upsert recovery key package"},
	} {
		t.Run(tc.table+" table dropped", func(t *testing.T) {
			store, dbPath := newFileBackedTestStore(t)
			ctx := context.Background()
			seedFaultInjectionAccount(t, store, "account-target")
			seedChangePasswordSession(t, store, "account-target", "caller")
			dropTable(t, dbPath, tc.table)

			if err := store.DeleteAccountForSession(ctx, "account-target", "hash", "caller"); err == nil || !strings.Contains(err.Error(), tc.wantDelete) {
				t.Fatalf("delete: expected %q, got %v", tc.wantDelete, err)
			}
			if tc.wantUpsert != "" {
				_, err := store.UpsertRecoveryKeyPackageForSession(ctx, stepUpTestPackage("account-target"), "hash", "caller")
				if err == nil || !strings.Contains(err.Error(), tc.wantUpsert) {
					t.Fatalf("upsert: expected %q, got %v", tc.wantUpsert, err)
				}
			}
			if _, err := store.FindAccountByID(ctx, "account-target"); err != nil {
				t.Fatalf("a failed delete must roll back: %v", err)
			}
		})
	}
}
