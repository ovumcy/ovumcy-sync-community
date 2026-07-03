package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDeleteAccountErasesBlobDeviceAndSessionThenIsIdempotent(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	ctx := context.Background()
	result, err := auth.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := syncService.AttachDevice(ctx, result.AccountID, "device-12345", "Pixel 7"); err != nil {
		t.Fatalf("attach device: %v", err)
	}

	ciphertext := []byte("ciphertext-only-payload")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, result.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	if _, err := syncService.PutRecoveryKeyPackage(ctx, result.AccountID, PutRecoveryKeyPackageInput{
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: strings.Repeat("c", 16),
	}); err != nil {
		t.Fatalf("put recovery key package: %v", err)
	}

	// The session used to perform the delete must itself stop authenticating
	// afterward — deletion erases the account the session belongs to, so
	// there is no "current session survives" carve-out here (unlike
	// ChangePassword, which deliberately keeps the caller's own session
	// alive).
	if _, err := auth.Authenticate(ctx, result.SessionToken); err != nil {
		t.Fatalf("expected session valid before delete, got %v", err)
	}

	if err := auth.DeleteAccount(ctx, result.AccountID); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	if _, err := auth.Authenticate(ctx, result.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected session revoked after account delete, got %v", err)
	}

	if _, err := syncService.GetBlob(ctx, result.AccountID); err != ErrBlobNotFound {
		t.Fatalf("expected blob gone after account delete, got %v", err)
	}

	if _, err := syncService.GetRecoveryKeyPackage(ctx, result.AccountID); err != ErrRecoveryPackageNotFound {
		t.Fatalf("expected recovery key package gone after account delete, got %v", err)
	}

	if _, err := auth.Login(ctx, "owner@example.com", "correct horse battery staple"); err != ErrInvalidCredentials {
		t.Fatalf("expected login to fail for a deleted account, got %v", err)
	}

	// Idempotent repeat: the account is already gone, so a second call must
	// report success rather than surfacing db.ErrNotFound to the caller. A
	// client retrying DELETE /account after a dropped response should see
	// the same "your data is gone" outcome both times.
	if err := auth.DeleteAccount(ctx, result.AccountID); err != nil {
		t.Fatalf("expected idempotent repeat delete to succeed, got %v", err)
	}
}

func TestDeleteAccountUnknownAccountIsIdempotentNoOp(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)

	if err := auth.DeleteAccount(context.Background(), "never-existed"); err != nil {
		t.Fatalf("expected no error deleting an account that never existed, got %v", err)
	}
}

func TestDeleteAccountDoesNotTouchOtherAccounts(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	ctx := context.Background()
	target, err := auth.Register(ctx, "target@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register target: %v", err)
	}
	bystander, err := auth.Register(ctx, "bystander@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register bystander: %v", err)
	}

	ciphertext := []byte("bystander-ciphertext")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, bystander.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("put bystander blob: %v", err)
	}

	if err := auth.DeleteAccount(ctx, target.AccountID); err != nil {
		t.Fatalf("delete target account: %v", err)
	}

	if _, err := auth.Authenticate(ctx, bystander.SessionToken); err != nil {
		t.Fatalf("expected bystander session to remain valid, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, bystander.AccountID); err != nil {
		t.Fatalf("expected bystander blob to remain, got %v", err)
	}
	if _, err := auth.Login(ctx, "bystander@example.com", "correct horse battery staple"); err != nil {
		t.Fatalf("expected bystander login to keep working, got %v", err)
	}

	if _, err := auth.Authenticate(ctx, target.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected target session revoked, got %v", err)
	}
}
