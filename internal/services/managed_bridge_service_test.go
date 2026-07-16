package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestManagedBridgeRejectsInvalidAccountID(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	if _, err := bridgeService.CreateManagedSession(context.Background(), "bad"); err != ErrInvalidManagedAccount {
		t.Fatalf("expected ErrInvalidManagedAccount for short id, got %v", err)
	}
}

func TestManagedBridgeRejectsExistingSelfHostedAccount(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	result, err := authService.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := bridgeService.CreateManagedSession(context.Background(), result.AccountID); err != ErrInvalidManagedAccount {
		t.Fatalf("expected ErrInvalidManagedAccount for self-hosted account reuse, got %v", err)
	}
}

func TestManagedBridgePurgeRejectsInvalidAccountID(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	for _, id := range []string{"bad", "invalid*chars!", ""} {
		if err := bridgeService.PurgeManagedAccount(context.Background(), id); !errors.Is(err, ErrInvalidManagedAccount) {
			t.Fatalf("expected ErrInvalidManagedAccount for id %q, got %v", id, err)
		}
	}
}

func TestManagedBridgePurgeErasesBlobDeviceAndSessionThenIsIdempotent(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	ctx := context.Background()
	const accountID = "managedacct1234"

	session, err := bridgeService.CreateManagedSession(ctx, accountID)
	if err != nil {
		t.Fatalf("create managed session: %v", err)
	}

	if _, err := syncService.AttachDevice(ctx, accountID, "device-12345", "Pixel 7"); err != nil {
		t.Fatalf("attach device: %v", err)
	}

	ciphertext := []byte("managed-ciphertext-payload")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, accountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	if _, err := syncService.PutRecoveryKeyPackage(ctx, accountID, PutRecoveryKeyPackageInput{
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: strings.Repeat("c", 16),
	}); err != nil {
		t.Fatalf("put recovery key package: %v", err)
	}

	if _, err := authService.Authenticate(ctx, session.SessionToken); err != nil {
		t.Fatalf("expected managed session valid before purge, got %v", err)
	}

	if err := bridgeService.PurgeManagedAccount(ctx, accountID); err != nil {
		t.Fatalf("purge managed account: %v", err)
	}

	if _, err := authService.Authenticate(ctx, session.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected managed session revoked after purge, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, accountID); err != ErrBlobNotFound {
		t.Fatalf("expected encrypted blob gone after purge, got %v", err)
	}
	if _, err := syncService.GetRecoveryKeyPackage(ctx, accountID); err != ErrRecoveryPackageNotFound {
		t.Fatalf("expected recovery key package gone after purge, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, accountID); err != nil || count != 0 {
		t.Fatalf("expected zero devices after purge, got count=%d err=%v", count, err)
	}
	if _, err := store.FindAccountByID(ctx, accountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected managed account row gone after purge, got %v", err)
	}

	// A repeat purge of the now-missing account must report success so the
	// managed caller can retry after a dropped response.
	if err := bridgeService.PurgeManagedAccount(ctx, accountID); err != nil {
		t.Fatalf("expected idempotent repeat purge to succeed, got %v", err)
	}
}

func TestManagedBridgePurgeUnknownAccountIsIdempotentNoOp(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	if err := bridgeService.PurgeManagedAccount(context.Background(), "neverexisted1234"); err != nil {
		t.Fatalf("expected purge of a never-existed managed account to succeed, got %v", err)
	}
}

func TestManagedBridgePurgeSurfacesAccountLookupStoreError(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	// Close the store so the account lookup fails with a generic store error
	// rather than db.ErrNotFound: the purge must surface it, never report a
	// false idempotent success that would tell the managed caller the account
	// is gone when it may still hold ciphertext.
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err := bridgeService.PurgeManagedAccount(context.Background(), "managedacct1234")
	if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected a store error from the account lookup, got %v", err)
	}
}

func TestManagedBridgePurgeSurfacesAccountDeleteStoreError(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	ctx := context.Background()
	const accountID = "managedacct1234"
	if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
		t.Fatalf("create managed session: %v", err)
	}

	// Drop a child table the account-delete transaction writes to while leaving
	// the accounts row intact: the lookup and managed-mode guard pass, then
	// DeleteAccount fails with a generic store error. The purge must surface it
	// instead of swallowing it as an idempotent no-op.
	dropTable(t, dbPath, "sessions")

	err := bridgeService.PurgeManagedAccount(ctx, accountID)
	if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected a store error from the account deletion, got %v", err)
	}
}

func TestManagedBridgePurgeRefusesSelfHostedAccount(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	ctx := context.Background()
	registered, err := authService.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	ciphertext := []byte("self-hosted-ciphertext")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, registered.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	// The bridge credential must never erase a self-hosted user's data, even
	// when handed that account's raw id.
	if err := bridgeService.PurgeManagedAccount(ctx, registered.AccountID); !errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected ErrInvalidManagedAccount for self-hosted account, got %v", err)
	}

	if _, err := authService.Authenticate(ctx, registered.SessionToken); err != nil {
		t.Fatalf("expected self-hosted session to survive refused purge, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, registered.AccountID); err != nil {
		t.Fatalf("expected self-hosted blob to survive refused purge, got %v", err)
	}
	if _, err := store.FindAccountByID(ctx, registered.AccountID); err != nil {
		t.Fatalf("expected self-hosted account row to survive refused purge, got %v", err)
	}
}

func TestExistingOrCreatedAtPrefersExistingTimestamp(t *testing.T) {
	now := time.Now().UTC()
	existing := now.Add(-time.Hour)

	if got := existingOrCreatedAt(models.Account{}, now); !got.Equal(now) {
		t.Fatalf("expected fallback timestamp, got %s", got)
	}
	if got := existingOrCreatedAt(models.Account{CreatedAt: existing}, now); !got.Equal(existing) {
		t.Fatalf("expected existing timestamp, got %s", got)
	}
}
