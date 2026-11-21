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
			if err := store.DeleteAccountForSession(ctx, tc.accountID, tc.verifiedHash, false, tc.tokenHash); !errors.Is(err, tc.want) {
				t.Fatalf("delete: expected %v, got %v", tc.want, err)
			}
			pkg := stepUpTestPackage(tc.accountID)
			if _, err := store.UpsertRecoveryKeyPackageForSession(ctx, pkg, tc.verifiedHash, false, tc.tokenHash); !errors.Is(err, tc.want) {
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

	stored, err := store.UpsertRecoveryKeyPackageForSession(ctx, stepUpTestPackage("account-target"), "hash", false, "caller")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if loaded, err := store.GetRecoveryKeyPackage(ctx, "account-target"); err != nil || loaded.WrapNonceHex != stored.WrapNonceHex {
		t.Fatalf("expected the package stored, got %#v / %v", loaded, err)
	}

	if err := store.DeleteAccountForSession(ctx, "account-target", "hash", false, "caller"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.FindAccountByID(ctx, "account-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the account erased, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "caller"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the caller's session erased, got %v", err)
	}
}

// TestStepUpWritesRefuseAFlippedTOTPState: a write judged under one TOTP
// enrollment refuses once the stored one differs — the erase, the overwrite
// and the device removal alike, in both directions — and a removal judged as
// enrolled also holds the hash its password was verified against.
func TestStepUpWritesRefuseAFlippedTOTPState(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	seedFaultInjectionAccount(t, store, "account-target")
	seedChangePasswordSession(t, store, "account-target", "caller")
	if err := attachForSession(store, "account-target", "caller", "device-target1", 10); err != nil {
		t.Fatalf("attach: %v", err)
	}

	assertRefusals := func(t *testing.T, verifiedTOTPEnabled bool) {
		t.Helper()
		if err := store.DeleteAccountForSession(ctx, "account-target", "hash", verifiedTOTPEnabled, "caller"); !errors.Is(err, ErrTOTPStateChanged) {
			t.Fatalf("delete: expected ErrTOTPStateChanged, got %v", err)
		}
		pkg := stepUpTestPackage("account-target")
		if _, err := store.UpsertRecoveryKeyPackageForSession(ctx, pkg, "hash", verifiedTOTPEnabled, "caller"); !errors.Is(err, ErrTOTPStateChanged) {
			t.Fatalf("upsert: expected ErrTOTPStateChanged, got %v", err)
		}
		if err := store.DeleteDevice(ctx, "account-target", "caller", "device-target1", verifiedTOTPEnabled, "hash"); !errors.Is(err, ErrTOTPStateChanged) {
			t.Fatalf("delete device: expected ErrTOTPStateChanged, got %v", err)
		}
	}

	// Judged as enrolled, stored without TOTP.
	assertRefusals(t, true)

	// An enrollment on the same session commits while a request judged
	// without TOTP is in flight.
	if _, err := store.db.ExecContext(ctx, `UPDATE accounts SET totp_enabled = 1 WHERE id = ?`, "account-target"); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	assertRefusals(t, false)

	if err := store.DeleteDevice(ctx, "account-target", "caller", "device-target1", true, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete device with a moved hash: expected ErrConflict, got %v", err)
	}

	if _, err := store.FindAccountByID(ctx, "account-target"); err != nil {
		t.Fatalf("a refused delete must keep the account: %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, "account-target"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused upsert must not write, got %v", err)
	}
	if got := deviceCount(t, store, "account-target"); got != 1 {
		t.Fatalf("a refused removal must keep the device, got %d devices", got)
	}

	if err := store.DeleteDevice(ctx, "account-target", "caller", "device-target1", true, "hash"); err != nil {
		t.Fatalf("delete device: %v", err)
	}
	if got := deviceCount(t, store, "account-target"); got != 0 {
		t.Fatalf("expected the device removed, got %d devices", got)
	}
}

func TestStepUpWritesSurfaceStoreFailures(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		ctx := context.Background()
		if err := store.DeleteAccountForSession(ctx, "a", "hash", false, "caller"); err == nil || !strings.Contains(err.Error(), "begin delete account") {
			t.Fatalf("delete: expected a begin error, got %v", err)
		}
		if _, err := store.UpsertRecoveryKeyPackageForSession(ctx, stepUpTestPackage("a"), "hash", false, "caller"); err == nil || !strings.Contains(err.Error(), "begin upsert recovery key package") {
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

			if err := store.DeleteAccountForSession(ctx, "account-target", "hash", false, "caller"); err == nil || !strings.Contains(err.Error(), tc.wantDelete) {
				t.Fatalf("delete: expected %q, got %v", tc.wantDelete, err)
			}
			if tc.wantUpsert != "" {
				_, err := store.UpsertRecoveryKeyPackageForSession(ctx, stepUpTestPackage("account-target"), "hash", false, "caller")
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
