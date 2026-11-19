package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A managed session stores a first package with no step-up but never replaces
// one; a revoked session writes nothing at all.
func TestPutRecoveryKeyManagedAccountStoresOnlyAFirstPackage(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	bridge := NewManagedBridgeService(store, auth)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	ctx := context.Background()

	session, err := bridge.CreateManagedSession(ctx, "managedacct3456")
	if err != nil {
		t.Fatalf("managed session: %v", err)
	}

	revoked := managedStepUp(session)
	revoked.SessionTokenHash = "not-a-live-session"
	if _, err := syncService.PutRecoveryKeyPackage(ctx, session.AccountID, revoked, validRecoveryKeyPackageInput()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked session: expected ErrUnauthorized, got %v", err)
	}

	first, err := syncService.PutRecoveryKeyPackage(ctx, session.AccountID, managedStepUp(session), validRecoveryKeyPackageInput())
	if err != nil {
		t.Fatalf("first put: %v", err)
	}

	changed := validRecoveryKeyPackageInput()
	changed.PhraseFingerprintHex = strings.Repeat("d", 16)
	if _, err := syncService.PutRecoveryKeyPackage(ctx, session.AccountID, managedStepUp(session), changed); !errors.Is(err, ErrManagedRecoveryKeyOverwrite) {
		t.Fatalf("changed package: expected ErrManagedRecoveryKeyOverwrite, got %v", err)
	}
	loaded, err := syncService.GetRecoveryKeyPackage(ctx, session.AccountID)
	if err != nil || loaded.PhraseFingerprintHex != first.PhraseFingerprintHex {
		t.Fatalf("expected the first package kept, got %#v / %v", loaded, err)
	}
}

// The managed first put skips only the password: the package is still
// validated, and an account holding TOTP still needs the code. Neither
// refusal stores anything.
func TestPutRecoveryKeyManagedFirstPutValidatesAndAsksForTOTP(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	bridge := NewManagedBridgeService(store, auth)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	ctx := context.Background()

	session, err := bridge.CreateManagedSession(ctx, "managedacct5678")
	if err != nil {
		t.Fatalf("managed session: %v", err)
	}

	invalid := validRecoveryKeyPackageInput()
	invalid.PhraseFingerprintHex = "not-hex"
	if _, err := syncService.PutRecoveryKeyPackage(ctx, session.AccountID, managedStepUp(session), invalid); !errors.Is(err, ErrInvalidRecoveryPackage) {
		t.Fatalf("invalid package: expected ErrInvalidRecoveryPackage, got %v", err)
	}

	if err := store.UpdateTOTPSecretAndEnabled(ctx, session.AccountID, "ciphertext-placeholder", true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	if _, err := syncService.PutRecoveryKeyPackage(ctx, session.AccountID, managedStepUp(session), validRecoveryKeyPackageInput()); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("totp-enabled managed account: expected ErrTOTPNotConfigured, got %v", err)
	}

	if _, err := syncService.GetRecoveryKeyPackage(ctx, session.AccountID); !errors.Is(err, ErrRecoveryPackageNotFound) {
		t.Fatalf("expected no package stored, got %v", err)
	}
}

func managedStepUp(result AuthResult) StepUp {
	stepUp := ownerStepUp(result)
	stepUp.CurrentPassword = ""
	return stepUp
}
