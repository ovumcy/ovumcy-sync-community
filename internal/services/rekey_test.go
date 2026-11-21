package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func rekeyBlobInput(payload string, generation int64) PutBlobInput {
	sum := sha256.Sum256([]byte(payload))
	return PutBlobInput{
		SchemaVersion:  1,
		Generation:     generation,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     []byte(payload),
	}
}

func rekeyedPackageInput() PutRecoveryKeyPackageInput {
	input := validRecoveryKeyPackageInput()
	input.WrappedMasterKeyHex = strings.Repeat("e", 96)
	input.PhraseFingerprintHex = strings.Repeat("f", 16)
	return input
}

func newRekeyFixture(t *testing.T) (*SyncService, AuthResult) {
	t.Helper()
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	registered, err := auth.Register(context.Background(), "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return syncService, registered
}

// seedRekey stores the k1 package and a blob at base through the route.
func seedRekey(t *testing.T, syncService *SyncService, registered AuthResult, base int64) {
	t.Helper()
	if _, _, err := syncService.Rekey(context.Background(), registered.AccountID, ownerStepUp(registered), RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               rekeyBlobInput("sealed-under-k1", base),
		ExpectedGeneration: expectGeneration(0),
	}); err != nil {
		t.Fatalf("seed rekey: %v", err)
	}
}

func assertRekeyState(t *testing.T, syncService *SyncService, accountID string, fingerprint string, ciphertext string) {
	t.Helper()
	pkg, err := syncService.GetRecoveryKeyPackage(context.Background(), accountID)
	if err != nil || pkg.PhraseFingerprintHex != fingerprint {
		t.Fatalf("package fingerprint = %q (err %v), want %q", pkg.PhraseFingerprintHex, err, fingerprint)
	}
	blob, err := syncService.GetBlob(context.Background(), accountID)
	if err != nil || string(blob.Ciphertext) != ciphertext {
		t.Fatalf("blob = %q (err %v), want %q", blob.Ciphertext, err, ciphertext)
	}
}

func TestRekeyFirstSetupStoresPackageAndBlob(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	base := time.Now().UTC().UnixMilli()
	seedRekey(t, syncService, registered, base)
	assertRekeyState(t, syncService, registered.AccountID, strings.Repeat("c", 16), "sealed-under-k1")
}

func TestRekeyReplacesPackageAndBlobTogether(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	seedRekey(t, syncService, registered, base)

	pkg, blob, err := syncService.Rekey(ctx, registered.AccountID, ownerStepUp(registered), RekeyInput{
		RecoveryKey:        rekeyedPackageInput(),
		Blob:               rekeyBlobInput("sealed-under-k2", base+1),
		ExpectedGeneration: expectGeneration(base),
	})
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if pkg.PhraseFingerprintHex != strings.Repeat("f", 16) || blob.Generation != base+1 {
		t.Fatalf("unexpected result %#v / generation %d", pkg, blob.Generation)
	}
	assertRekeyState(t, syncService, registered.AccountID, strings.Repeat("f", 16), "sealed-under-k2")
}

// The T3-2 hazard: a refused blob write must leave the old package, so the
// old phrase still opens the stored blob.
func TestRekeyRefusedBlobLeavesThePackage(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	seedRekey(t, syncService, registered, base)

	for name, expected := range map[string]int64{"mismatch": base - 1, "no-row expectation": 0} {
		_, _, err := syncService.Rekey(ctx, registered.AccountID, ownerStepUp(registered), RekeyInput{
			RecoveryKey:        rekeyedPackageInput(),
			Blob:               rekeyBlobInput("sealed-under-k2", base+1),
			ExpectedGeneration: expectGeneration(expected),
		})
		if !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("%s: expected ErrStaleGeneration, got %v", name, err)
		}
	}
	assertRekeyState(t, syncService, registered.AccountID, strings.Repeat("c", 16), "sealed-under-k1")
}

func TestRekeyRequiresExpectedGeneration(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	for name, expected := range map[string]*int64{"absent": nil, "negative": expectGeneration(-1)} {
		_, _, err := syncService.Rekey(context.Background(), registered.AccountID, ownerStepUp(registered), RekeyInput{
			RecoveryKey:        validRecoveryKeyPackageInput(),
			Blob:               rekeyBlobInput("sealed-under-k1", time.Now().UTC().UnixMilli()),
			ExpectedGeneration: expected,
		})
		if !errors.Is(err, ErrInvalidBlob) {
			t.Fatalf("%s: expected ErrInvalidBlob, got %v", name, err)
		}
	}
}

// A differing package checks the password before either body is validated,
// as PUT /sync/recovery-key does.
func TestRekeyChecksPasswordBeforeValidation(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	wrong := ownerStepUp(registered)
	wrong.CurrentPassword = "not the password"
	badPackage := validRecoveryKeyPackageInput()
	badPackage.WrappedMasterKeyHex = "zz"
	badBlob := rekeyBlobInput("x", time.Now().UTC().UnixMilli())
	badBlob.ChecksumSHA256 = "bad"

	_, _, err := syncService.Rekey(context.Background(), registered.AccountID, wrong, RekeyInput{
		RecoveryKey:        badPackage,
		Blob:               badBlob,
		ExpectedGeneration: expectGeneration(0),
	})
	if !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}

	_, _, err = syncService.Rekey(context.Background(), registered.AccountID, ownerStepUp(registered), RekeyInput{
		RecoveryKey:        badPackage,
		Blob:               rekeyBlobInput("x", time.Now().UTC().UnixMilli()),
		ExpectedGeneration: expectGeneration(0),
	})
	if !errors.Is(err, ErrInvalidRecoveryPackage) {
		t.Fatalf("short wrapped key: expected ErrInvalidRecoveryPackage, got %v", err)
	}
	_, _, err = syncService.Rekey(context.Background(), registered.AccountID, ownerStepUp(registered), RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               badBlob,
		ExpectedGeneration: expectGeneration(0),
	})
	if !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("bad checksum: expected ErrInvalidBlob, got %v", err)
	}
	if _, err := syncService.GetRecoveryKeyPackage(context.Background(), registered.AccountID); !errors.Is(err, ErrRecoveryPackageNotFound) {
		t.Fatalf("a refused rekey stored a package: %v", err)
	}
}

func TestRekeyUnchangedPackageNeedsNoPassword(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	base := time.Now().UTC().UnixMilli()
	seedRekey(t, syncService, registered, base)
	noPassword := ownerStepUp(registered)
	noPassword.CurrentPassword = ""

	_, _, err := syncService.Rekey(context.Background(), registered.AccountID, noPassword, RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               rekeyBlobInput("still-k1", base+1),
		ExpectedGeneration: expectGeneration(base),
	})
	if err != nil {
		t.Fatalf("unchanged package: %v", err)
	}
	assertRekeyState(t, syncService, registered.AccountID, strings.Repeat("c", 16), "still-k1")
}

func TestRekeyManagedAccountStoresOnlyAFirstPackage(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	bridge := NewManagedBridgeService(store, auth)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 2, MaxBlobBytes: 1 << 20})
	ctx := context.Background()
	session, err := bridge.CreateManagedSession(ctx, "managedacct3456")
	if err != nil {
		t.Fatalf("managed session: %v", err)
	}
	base := time.Now().UTC().UnixMilli()

	if _, _, err := syncService.Rekey(ctx, session.AccountID, managedStepUp(session), RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               rekeyBlobInput("sealed-under-k1", base),
		ExpectedGeneration: expectGeneration(0),
	}); err != nil {
		t.Fatalf("first managed rekey: %v", err)
	}
	_, _, err = syncService.Rekey(ctx, session.AccountID, managedStepUp(session), RekeyInput{
		RecoveryKey:        rekeyedPackageInput(),
		Blob:               rekeyBlobInput("sealed-under-k2", base+1),
		ExpectedGeneration: expectGeneration(base),
	})
	if !errors.Is(err, ErrManagedRecoveryKeyOverwrite) {
		t.Fatalf("managed overwrite: expected ErrManagedRecoveryKeyOverwrite, got %v", err)
	}
	assertRekeyState(t, syncService, session.AccountID, strings.Repeat("c", 16), "sealed-under-k1")
}
