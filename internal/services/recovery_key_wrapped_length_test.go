package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// A row stored before writes required exactly 96 hex characters keeps working:
// reads return it and its identical re-put is still the no-op, while a new
// write of the old shape is refused and leaves the row in place.
func TestPutRecoveryKeyLegacyWrappedKeyRowStaysUsable(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	legacyInput := validRecoveryKeyPackageInput()
	legacyInput.WrappedMasterKeyHex = strings.Repeat("b", 64)
	storedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := store.UpsertRecoveryKeyPackage(ctx, models.RecoveryKeyPackage{
		AccountID:            registered.AccountID,
		Algorithm:            legacyInput.Algorithm,
		KDF:                  legacyInput.KDF,
		MnemonicWordCount:    legacyInput.MnemonicWordCount,
		WrapNonceHex:         legacyInput.WrapNonceHex,
		WrappedMasterKeyHex:  legacyInput.WrappedMasterKeyHex,
		PhraseFingerprintHex: legacyInput.PhraseFingerprintHex,
		UpdatedAt:            storedAt,
	}); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	loaded, err := syncService.GetRecoveryKeyPackage(ctx, registered.AccountID)
	if err != nil || loaded.WrappedMasterKeyHex != legacyInput.WrappedMasterKeyHex {
		t.Fatalf("expected the legacy row on read, got %#v, %v", loaded, err)
	}

	noPassword := ownerStepUp(registered)
	noPassword.CurrentPassword = ""
	got, err := syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, noPassword, legacyInput)
	if err != nil || !got.UpdatedAt.Equal(storedAt) {
		t.Fatalf("expected the legacy row back from its identical re-put, got %#v, %v", got, err)
	}

	differing := legacyInput
	differing.PhraseFingerprintHex = strings.Repeat("d", 16)
	if _, err := syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, ownerStepUp(registered), differing); err != ErrInvalidRecoveryPackage {
		t.Fatalf("expected ErrInvalidRecoveryPackage for a new 64-hex write, got %v", err)
	}
	loaded, err = syncService.GetRecoveryKeyPackage(ctx, registered.AccountID)
	if err != nil || !loaded.UpdatedAt.Equal(storedAt) || loaded.PhraseFingerprintHex != legacyInput.PhraseFingerprintHex {
		t.Fatalf("expected the refused write to leave the legacy row, got %#v, %v", loaded, err)
	}
}
