package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A re-put of the stored package, in any letter case or surrounding
// whitespace, needs no password, returns the stored row and writes nothing.
func TestPutRecoveryKeyIdenticalRePutNeedsNoStepUp(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	first := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	syncService.now = func() time.Time { return first }
	stored, err := syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, ownerStepUp(registered), validRecoveryKeyPackageInput())
	if err != nil {
		t.Fatalf("initial put: %v", err)
	}

	syncService.now = func() time.Time { return first.Add(time.Hour) }
	rePut := validRecoveryKeyPackageInput()
	rePut.Algorithm = " XChaCha20Poly1305 "
	rePut.WrapNonceHex = strings.ToUpper(rePut.WrapNonceHex)
	rePut.WrappedMasterKeyHex = " " + strings.ToUpper(rePut.WrappedMasterKeyHex)
	noPassword := ownerStepUp(registered)
	noPassword.CurrentPassword = ""

	got, err := syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, noPassword, rePut)
	if err != nil {
		t.Fatalf("identical re-put without a password: %v", err)
	}
	if !got.UpdatedAt.Equal(first) || got.WrappedMasterKeyHex != stored.WrappedMasterKeyHex || got.Algorithm != stored.Algorithm {
		t.Fatalf("expected the stored package back, got %#v want %#v", got, stored)
	}
	loaded, err := syncService.GetRecoveryKeyPackage(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !loaded.UpdatedAt.Equal(first) {
		t.Fatalf("a no-op re-put must not write: updated_at %v, want %v", loaded.UpdatedAt, first)
	}
}

// A package differing from the stored one in any single field is an
// overwrite, so it still needs the password.
func TestPutRecoveryKeyDifferingPackageStillNeedsStepUp(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, ownerStepUp(registered), validRecoveryKeyPackageInput()); err != nil {
		t.Fatalf("initial put: %v", err)
	}
	noPassword := ownerStepUp(registered)
	noPassword.CurrentPassword = ""

	cases := map[string]func(*PutRecoveryKeyPackageInput){
		"algorithm":           func(in *PutRecoveryKeyPackageInput) { in.Algorithm = "aes" },
		"kdf":                 func(in *PutRecoveryKeyPackageInput) { in.KDF = "scrypt" },
		"mnemonic word count": func(in *PutRecoveryKeyPackageInput) { in.MnemonicWordCount = 24 },
		"wrap nonce":          func(in *PutRecoveryKeyPackageInput) { in.WrapNonceHex = strings.Repeat("d", 48) },
		"wrapped master key":  func(in *PutRecoveryKeyPackageInput) { in.WrappedMasterKeyHex = strings.Repeat("e", 96) },
		"phrase fingerprint":  func(in *PutRecoveryKeyPackageInput) { in.PhraseFingerprintHex = strings.Repeat("f", 16) },
	}
	for name, mutate := range cases {
		input := validRecoveryKeyPackageInput()
		mutate(&input)
		if _, err := syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, noPassword, input); !errors.Is(err, ErrInvalidCurrentPassword) {
			t.Fatalf("%s: expected ErrInvalidCurrentPassword, got %v", name, err)
		}
	}
	loaded, err := syncService.GetRecoveryKeyPackage(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	want := validRecoveryKeyPackageInput()
	if loaded.WrappedMasterKeyHex != want.WrappedMasterKeyHex || loaded.PhraseFingerprintHex != want.PhraseFingerprintHex {
		t.Fatalf("a refused overwrite must keep the stored package, got %#v", loaded)
	}
}

// On a TOTP-enrolled account the identical re-put needs neither the password
// nor a code; a differing package still needs both.
func TestPutRecoveryKeyIdenticalRePutOnTOTPAccountNeedsNoCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	input := validRecoveryKeyInput(strings.Repeat("c", 16))
	if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(f.code()), input); err != nil {
		t.Fatalf("initial put: %v", err)
	}

	bare := StepUp{SessionTokenHash: f.sessionHash}
	if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, bare, input); err != nil {
		t.Fatalf("identical re-put without password or code: %v", err)
	}

	differing := validRecoveryKeyInput(strings.Repeat("d", 16))
	if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(""), differing); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("a differing package without a code: expected ErrTOTPInvalidCode, got %v", err)
	}
	if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, bare, differing); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("a differing package without a password: expected ErrInvalidCurrentPassword, got %v", err)
	}
}

func TestPutRecoveryKeySurfacesStoreErrorReadingStoredPackage(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	dropTable(t, dbPath, "recovery_key_packages")

	// Without a password: only the read before the step-up can answer with
	// anything but ErrInvalidCurrentPassword.
	noPassword := ownerStepUp(registered)
	noPassword.CurrentPassword = ""
	_, err = syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, noPassword, validRecoveryKeyPackageInput())
	if err == nil || errors.Is(err, ErrInvalidCurrentPassword) || errors.Is(err, ErrInvalidRecoveryPackage) {
		t.Fatalf("expected the store error, got %v", err)
	}
}
