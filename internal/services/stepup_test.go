package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

const stepUpTestPassword = "correct horse battery staple"

// ownerStepUp is the step-up a session from Register/Login/CreateManagedSession
// carries with the fixtures' password.
func ownerStepUp(result AuthResult) StepUp {
	return StepUp{
		SessionTokenHash: security.HashToken(result.SessionToken),
		CurrentPassword:  stepUpTestPassword,
	}
}

func validRecoveryKeyPackageInput() PutRecoveryKeyPackageInput {
	return PutRecoveryKeyPackageInput{
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: strings.Repeat("c", 16),
	}
}

func TestVerifyStepUp(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	ctx := context.Background()

	registered, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	account, err := verifyStepUp(ctx, store, registered.AccountID, stepUpTestPassword)
	if err != nil {
		t.Fatalf("expected the right password to confirm, got %v", err)
	}
	if account.ID != registered.AccountID || account.PasswordHash == "" {
		t.Fatalf("expected the verified account returned, got %#v", account)
	}
	for _, wrong := range []string{"wrong password here", ""} {
		if _, err := verifyStepUp(ctx, store, registered.AccountID, wrong); err != ErrInvalidCurrentPassword {
			t.Fatalf("expected ErrInvalidCurrentPassword for %q, got %v", wrong, err)
		}
	}
	if _, err := verifyStepUp(ctx, store, "missing-account", "any"); err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for an unknown account, got %v", err)
	}
}

// Managed accounts carry no password; their sessions come only from the
// managed bridge, so the step-up must not lock them out.
func TestVerifyStepUpPassesManagedAccount(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	bridge := NewManagedBridgeService(store, auth)
	ctx := context.Background()

	session, err := bridge.CreateManagedSession(ctx, "managedacct1234")
	if err != nil {
		t.Fatalf("create managed session: %v", err)
	}
	if _, err := verifyStepUp(ctx, store, session.AccountID, ""); err != nil {
		t.Fatalf("expected a managed account to pass, got %v", err)
	}
}

func TestVerifyStepUpSurfacesStoreError(t *testing.T) {
	store := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	_, err := verifyStepUp(context.Background(), store, "any-account", "any")
	if err == nil || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected a store-failure error, got %v", err)
	}
}

func TestStepUpWriteError(t *testing.T) {
	other := errors.New("boom")
	for _, tc := range []struct{ in, want error }{
		{db.ErrConflict, ErrInvalidCurrentPassword},
		{db.ErrSessionRevoked, ErrUnauthorized},
		{db.ErrNotFound, ErrUnauthorized},
		{other, other},
		{nil, nil},
	} {
		if got := stepUpWriteError(tc.in); got != tc.want {
			t.Fatalf("stepUpWriteError(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A session revoked after it authenticated the request (a password change on
// another device, a TOTP enrollment) must not erase the account or overwrite
// its recovery key with the password alone.
func TestStepUpWritesRefuseARevokedCallerSession(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1024})
	ctx := context.Background()

	caller, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := store.DeleteSessionByTokenHash(ctx, security.HashToken(caller.SessionToken)); err != nil {
		t.Fatalf("revoke the caller's session: %v", err)
	}

	if _, err := syncService.PutRecoveryKeyPackage(ctx, caller.AccountID, ownerStepUp(caller), validRecoveryKeyPackageInput()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("put recovery key: expected ErrUnauthorized, got %v", err)
	}
	if _, err := syncService.GetRecoveryKeyPackage(ctx, caller.AccountID); !errors.Is(err, ErrRecoveryPackageNotFound) {
		t.Fatalf("expected no package written, got %v", err)
	}
	if err := auth.DeleteAccount(ctx, caller.AccountID, ownerStepUp(caller)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("delete account: expected ErrUnauthorized, got %v", err)
	}
	if _, err := store.FindAccountByID(ctx, caller.AccountID); err != nil {
		t.Fatalf("expected the account kept: %v", err)
	}
}

func TestStepUpWritesRefuseAWrongPassword(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1024})
	ctx := context.Background()

	caller, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	wrong := StepUp{SessionTokenHash: security.HashToken(caller.SessionToken), CurrentPassword: "wrong password here"}

	invalid := validRecoveryKeyPackageInput()
	invalid.KDF = "wrong"
	if _, err := syncService.PutRecoveryKeyPackage(ctx, caller.AccountID, wrong, invalid); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("put recovery key: expected the password checked before the body, got %v", err)
	}
	if err := auth.DeleteAccount(ctx, caller.AccountID, wrong); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("delete account: expected ErrInvalidCurrentPassword, got %v", err)
	}
	if _, err := store.FindAccountByID(ctx, caller.AccountID); err != nil {
		t.Fatalf("expected the account kept: %v", err)
	}
}

func TestStepUpWritesSurfaceStoreErrors(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1024})
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	ctx := context.Background()

	if err := auth.DeleteAccount(ctx, "any-account", StepUp{}); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("delete account: expected a store-failure error, got %v", err)
	}
	if _, err := syncService.PutRecoveryKeyPackage(ctx, "any-account", StepUp{}, validRecoveryKeyPackageInput()); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("put recovery key: expected a store-failure error, got %v", err)
	}
}
