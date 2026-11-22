package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// A vanished account, a malformed blob on the unchanged-package path and a
// revoked session each refuse the re-key and write nothing.
func TestRekeyRefusalsBeforeAndInsideTheWrite(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()

	if _, _, err := syncService.Rekey(ctx, "no-such-account", ownerStepUp(registered), RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               rekeyBlobInput("sealed-under-k1", base),
		ExpectedGeneration: expectGeneration(0),
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown account: expected ErrUnauthorized, got %v", err)
	}

	seedRekey(t, syncService, registered, base)

	malformed := rekeyBlobInput("sealed-under-k1-again", base+1)
	malformed.ChecksumSHA256 = strings.Repeat("0", 64)
	if _, _, err := syncService.Rekey(ctx, registered.AccountID, ownerStepUp(registered), RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               malformed,
		ExpectedGeneration: expectGeneration(base),
		KeepStoredPackage:  true,
	}); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("unchanged package with a bad checksum: expected ErrInvalidBlob, got %v", err)
	}

	revoked := ownerStepUp(registered)
	revoked.SessionTokenHash = "revoked-session"
	if _, _, err := syncService.Rekey(ctx, registered.AccountID, revoked, RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               rekeyBlobInput("sealed-under-k1-again", base+1),
		ExpectedGeneration: expectGeneration(base),
		KeepStoredPackage:  true,
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked session: expected ErrUnauthorized, got %v", err)
	}

	assertRekeyState(t, syncService, registered.AccountID, strings.Repeat("c", 16), "sealed-under-k1")
}

// The TOTP precheck's blob read failing surfaces as a store error, before the
// code is checked.
func TestRekeyTOTPPrecheckSurfacesStoreFailure(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp := NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)
	now := time.Date(2026, 7, 7, 10, 0, 5, 0, time.UTC)
	auth.now = func() time.Time { return now }
	totp.now = func() time.Time { return now }
	accountID, token, _, _ := enrollTOTP(t, auth, totp, now)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1 << 20})
	syncService.AttachTOTPCodeVerifier(totp)

	dropTable(t, dbPath, "encrypted_blobs")

	_, _, err := syncService.Rekey(context.Background(), accountID, StepUp{
		SessionTokenHash: security.HashToken(token),
		CurrentPassword:  totpWindowTestPassword,
		TOTPCode:         "000000",
	}, RekeyInput{
		RecoveryKey:        validRecoveryKeyInput(strings.Repeat("c", 16)),
		Blob:               rekeyBlobInput("sealed-under-k1", time.Now().UTC().UnixMilli()),
		ExpectedGeneration: expectGeneration(0),
	})
	if err == nil || errors.Is(err, ErrStaleGeneration) || errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("expected the precheck's store error, got %v", err)
	}
}
