package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestSyncServiceAttachDeviceAndBlobRoundTrip(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 16 << 20})

	result, err := auth.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	device, err := syncService.AttachDevice(
		context.Background(),
		result.AccountID,
		"device-12345",
		"Pixel 7",
	)
	if err != nil {
		t.Fatalf("attach device: %v", err)
	}
	if device.DeviceID != "device-12345" {
		t.Fatalf("unexpected device id: %#v", device)
	}

	ciphertext := []byte("ciphertext-only-payload")
	sum := sha256.Sum256(ciphertext)

	storedBlob, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	})
	if err != nil {
		t.Fatalf("put blob: %v", err)
	}
	if storedBlob.CiphertextSize != len(ciphertext) {
		t.Fatalf("unexpected blob size: %#v", storedBlob)
	}

	loadedBlob, err := syncService.GetBlob(context.Background(), result.AccountID)
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	if string(loadedBlob.Ciphertext) != string(ciphertext) {
		t.Fatalf("unexpected ciphertext: %#v", loadedBlob)
	}

	recoveryKeyPackage, err := syncService.PutRecoveryKeyPackage(
		context.Background(),
		result.AccountID,
		PutRecoveryKeyPackageInput{
			Algorithm:            "xchacha20poly1305",
			KDF:                  "bip39_seed_hkdf_sha256",
			MnemonicWordCount:    12,
			WrapNonceHex:         strings.Repeat("a", 48),
			WrappedMasterKeyHex:  strings.Repeat("b", 96),
			PhraseFingerprintHex: strings.Repeat("c", 16),
		},
	)
	if err != nil {
		t.Fatalf("put recovery key package: %v", err)
	}
	if recoveryKeyPackage.Algorithm != "xchacha20poly1305" {
		t.Fatalf("unexpected recovery key package: %#v", recoveryKeyPackage)
	}

	loadedRecoveryKeyPackage, err := syncService.GetRecoveryKeyPackage(
		context.Background(),
		result.AccountID,
	)
	if err != nil {
		t.Fatalf("get recovery key package: %v", err)
	}
	if loadedRecoveryKeyPackage.WrappedMasterKeyHex != strings.Repeat("b", 96) {
		t.Fatalf("unexpected wrapped recovery material: %#v", loadedRecoveryKeyPackage)
	}
}

func TestSyncServiceEnforcesDeviceLimit(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 1, MaxBlobBytes: 16 << 20})

	result, err := auth.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := syncService.AttachDevice(
		context.Background(),
		result.AccountID,
		"device-1aaaa",
		"Phone",
	); err != nil {
		t.Fatalf("first attach: %v", err)
	}

	_, err = syncService.AttachDevice(
		context.Background(),
		result.AccountID,
		"device-2bbbb",
		"Tablet",
	)
	if err != ErrTooManyDevices {
		t.Fatalf("expected ErrTooManyDevices, got %v", err)
	}
}

func TestSyncServiceCapabilitiesStaySelfHosted(t *testing.T) {
	syncService := NewSyncService(nil, SyncOptions{MaxDevices: 5, MaxBlobBytes: 8 << 20})

	capabilities := syncService.Capabilities()
	if capabilities.Mode != "self_hosted" {
		t.Fatalf("unexpected mode: %#v", capabilities)
	}
	if capabilities.PremiumActive {
		t.Fatalf("premium must stay false for community mode: %#v", capabilities)
	}
	if !capabilities.RecoverySupported {
		t.Fatalf("community mode should advertise wrapped recovery-package support: %#v", capabilities)
	}
	if capabilities.MaxBlobBytes != 8<<20 {
		t.Fatalf("expected configured blob limit in capabilities, got %#v", capabilities)
	}
}

func TestSyncServiceCapabilitiesForManagedAccount(t *testing.T) {
	syncService := NewSyncService(nil, SyncOptions{MaxDevices: 5, MaxBlobBytes: 8 << 20})

	capabilities := syncService.CapabilitiesForAccount(models.Account{
		ID:            "managedacct1234",
		Mode:          "managed",
		PremiumActive: true,
	})
	if capabilities.Mode != "managed" {
		t.Fatalf("unexpected managed mode: %#v", capabilities)
	}
	if !capabilities.SyncEnabled || !capabilities.PremiumActive {
		t.Fatalf("expected managed premium capabilities, got %#v", capabilities)
	}
}

func TestSyncServiceRejectsChecksumMismatchAndStaleGeneration(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 16 << 20})

	result, err := auth.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	ciphertext := []byte("ciphertext-only-payload")
	sum := sha256.Sum256(ciphertext)

	if _, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("seed put blob: %v", err)
	}

	if _, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     2,
		ChecksumSHA256: strings.Repeat("a", 64),
		Ciphertext:     ciphertext,
	}); err != ErrInvalidBlob {
		t.Fatalf("expected ErrInvalidBlob for checksum mismatch, got %v", err)
	}

	if _, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != ErrStaleGeneration {
		t.Fatalf("expected ErrStaleGeneration, got %v", err)
	}
}

func TestSyncServiceRejectsInvalidRecoveryKeyPackage(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 16 << 20})

	result, err := auth.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := syncService.PutRecoveryKeyPackage(context.Background(), result.AccountID, PutRecoveryKeyPackageInput{
		Algorithm:            "aes",
		KDF:                  "wrong",
		MnemonicWordCount:    8,
		WrapNonceHex:         "zz",
		WrappedMasterKeyHex:  "not-hex",
		PhraseFingerprintHex: "short",
	}); err != ErrInvalidRecoveryPackage {
		t.Fatalf("expected ErrInvalidRecoveryPackage, got %v", err)
	}
}

func TestSyncServiceRejectsOversizedBlob(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 8})

	result, err := auth.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	ciphertext := []byte("ciphertext-too-large")
	sum := sha256.Sum256(ciphertext)

	if _, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != ErrInvalidBlob {
		t.Fatalf("expected ErrInvalidBlob for oversized payload, got %v", err)
	}
}

func TestSyncServiceRejectsInvalidDeviceAndMissingReads(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 16 << 20})

	result, err := auth.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := syncService.AttachDevice(context.Background(), result.AccountID, "short", "P"); err != ErrInvalidDevice {
		t.Fatalf("expected ErrInvalidDevice, got %v", err)
	}
	if _, err := syncService.GetBlob(context.Background(), result.AccountID); err != ErrBlobNotFound {
		t.Fatalf("expected ErrBlobNotFound, got %v", err)
	}
	if _, err := syncService.GetRecoveryKeyPackage(context.Background(), result.AccountID); err != ErrRecoveryPackageNotFound {
		t.Fatalf("expected ErrRecoveryPackageNotFound, got %v", err)
	}
}

func TestSyncServiceManagedInactiveAccountDisablesSync(t *testing.T) {
	syncService := NewSyncService(nil, SyncOptions{MaxDevices: 5, MaxBlobBytes: 8 << 20})

	capabilities := syncService.CapabilitiesForAccount(models.Account{
		ID:            "managedacct1234",
		Mode:          "managed",
		PremiumActive: false,
	})
	if capabilities.Mode != "managed" {
		t.Fatalf("unexpected managed mode: %#v", capabilities)
	}
	if capabilities.SyncEnabled || capabilities.PremiumActive {
		t.Fatalf("expected inactive managed capabilities, got %#v", capabilities)
	}
}
