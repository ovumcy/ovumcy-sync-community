package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestSyncServiceAttachDeviceAndBlobRoundTrip(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, 2)

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
}

func TestSyncServiceEnforcesDeviceLimit(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, 1)

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
	syncService := NewSyncService(nil, 5)

	capabilities := syncService.Capabilities()
	if capabilities.Mode != "self_hosted" {
		t.Fatalf("unexpected mode: %#v", capabilities)
	}
	if capabilities.PremiumActive {
		t.Fatalf("premium must stay false for community mode: %#v", capabilities)
	}
	if capabilities.RecoverySupported {
		t.Fatalf("community mode must not claim managed recovery: %#v", capabilities)
	}
}

func TestSyncServiceRejectsChecksumMismatchAndStaleGeneration(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, 2)

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
