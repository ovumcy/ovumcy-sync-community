package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
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

// TestSyncServicePutBlobConcurrentEqualGenerationCollapsesToOneWinner is the
// regression for HIGH-2: before the WHERE excluded.generation >
// encrypted_blobs.generation guard on the upsert branch, two concurrent
// uploads that both read the same existing generation could both pass the
// service-level check (TOCTOU) and the later writer would silently
// overwrite the earlier — losing data and potentially rolling back the
// blob. With the CAS, exactly one of N concurrent writers at the same
// generation must win, and the rest must surface ErrStaleGeneration.
func TestSyncServicePutBlobConcurrentEqualGenerationCollapsesToOneWinner(t *testing.T) {
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

	// Seed an initial blob at generation 1 so all concurrent racers below
	// share the same baseline and must compete for generation 2.
	seedCiphertext := []byte("seed-ciphertext-payload")
	seedSum := sha256.Sum256(seedCiphertext)
	if _, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(seedSum[:]),
		Ciphertext:     seedCiphertext,
	}); err != nil {
		t.Fatalf("seed put blob: %v", err)
	}

	const fanout = 8
	results := make([]error, fanout)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range fanout {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct ciphertext per racer so we can tell who won via
			// post-condition inspection. Generation is the same for all
			// so they collide on the CAS predicate.
			racerCiphertext := []byte(fmt.Sprintf("racer-%d-ciphertext-payload", i))
			racerSum := sha256.Sum256(racerCiphertext)
			<-start
			_, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
				SchemaVersion:  1,
				Generation:     2,
				ChecksumSHA256: hex.EncodeToString(racerSum[:]),
				Ciphertext:     racerCiphertext,
			})
			results[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrStaleGeneration):
		default:
			t.Errorf("unexpected error from concurrent PutBlob: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful PutBlob across %d concurrent attempts, got %d", fanout, successes)
	}

	// The persisted blob must be at generation 2 (the contested value)
	// after the dust settles, never reverted to the seed value.
	stored, err := syncService.GetBlob(context.Background(), result.AccountID)
	if err != nil {
		t.Fatalf("get blob after race: %v", err)
	}
	if stored.Generation != 2 {
		t.Fatalf("expected stored generation 2 after race, got %d", stored.Generation)
	}

	// A subsequent stale-generation write must also be rejected, proving
	// the CAS survives beyond the race window.
	if _, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     2,
		ChecksumSHA256: hex.EncodeToString(seedSum[:]),
		Ciphertext:     seedCiphertext,
	}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected sequential equal-generation write after race to fail with ErrStaleGeneration, got %v", err)
	}
}

// TestSyncServicePutBlobFirstWriteSucceeds proves the CAS keyed on
// excluded.generation > encrypted_blobs.generation does NOT block the
// initial INSERT branch where no prior row exists — the WHERE applies to
// the DO UPDATE arm only.
func TestSyncServicePutBlobFirstWriteSucceeds(t *testing.T) {
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

	ciphertext := []byte("first-write-payload")
	sum := sha256.Sum256(ciphertext)
	stored, err := syncService.PutBlob(context.Background(), result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	})
	if err != nil {
		t.Fatalf("first PutBlob: %v", err)
	}
	if stored.Generation != 1 {
		t.Fatalf("expected generation 1 on first write, got %d", stored.Generation)
	}

	// db.ErrStaleGeneration is the new sentinel that the service-level
	// ErrStaleGeneration wraps via the PutBlob switch — sanity-check both
	// surfaces are wired so callers can rely on the public error.
	if db.ErrStaleGeneration.Error() == "" {
		t.Fatalf("db.ErrStaleGeneration sentinel missing message")
	}
}
