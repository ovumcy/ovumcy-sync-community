package db

import (
	"context"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestMigrationsBootstrapAndRepositories(t *testing.T) {
	store := openTestStore(t)

	now := time.Now().UTC()
	account, err := store.CreateAccount(context.Background(), models.Account{
		ID:           "account-1",
		Login:        "owner@example.com",
		PasswordHash: "hash",
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	if _, err := store.CreateSession(context.Background(), models.Session{
		ID:         "session-1",
		AccountID:  account.ID,
		TokenHash:  "token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := store.UpsertDevice(context.Background(), models.Device{
		AccountID:   account.ID,
		DeviceID:    "device-1",
		DeviceLabel: "Pixel 7",
		CreatedAt:   now,
		LastSeenAt:  now,
	}); err != nil {
		t.Fatalf("upsert device: %v", err)
	}

	if _, err := store.UpsertEncryptedBlob(context.Background(), models.EncryptedBlob{
		AccountID:      account.ID,
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Ciphertext:     []byte("ciphertext"),
		CiphertextSize: len("ciphertext"),
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("upsert encrypted blob: %v", err)
	}

	if _, err := store.UpsertRecoveryKeyPackage(context.Background(), models.RecoveryKeyPackage{
		AccountID:            account.ID,
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		WrappedMasterKeyHex:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PhraseFingerprintHex: "cccccccccccccccc",
		UpdatedAt:            now,
	}); err != nil {
		t.Fatalf("upsert recovery key package: %v", err)
	}

	if _, err := store.FindAccountByID(context.Background(), account.ID); err != nil {
		t.Fatalf("find account by id: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(context.Background(), "token-hash"); err != nil {
		t.Fatalf("find session by token hash: %v", err)
	}
	if _, err := store.FindDevice(context.Background(), account.ID, "device-1"); err != nil {
		t.Fatalf("find device: %v", err)
	}
	if _, err := store.GetEncryptedBlob(context.Background(), account.ID); err != nil {
		t.Fatalf("get encrypted blob: %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(context.Background(), account.ID); err != nil {
		t.Fatalf("get recovery key package: %v", err)
	}
}

func TestRepositoriesDoNotShareDeviceOwnershipAcrossAccounts(t *testing.T) {
	store := openTestStore(t)

	now := time.Now().UTC()
	for _, accountID := range []string{"account-1", "account-2"} {
		if _, err := store.CreateAccount(context.Background(), models.Account{
			ID:           accountID,
			Login:        accountID + "@example.com",
			PasswordHash: "hash",
			CreatedAt:    now,
		}); err != nil {
			t.Fatalf("create account %s: %v", accountID, err)
		}
	}

	for _, accountID := range []string{"account-1", "account-2"} {
		if _, err := store.UpsertDevice(context.Background(), models.Device{
			AccountID:   accountID,
			DeviceID:    "shared-device",
			DeviceLabel: accountID,
			CreatedAt:   now,
			LastSeenAt:  now,
		}); err != nil {
			t.Fatalf("upsert device for %s: %v", accountID, err)
		}
	}

	deviceOne, err := store.FindDevice(context.Background(), "account-1", "shared-device")
	if err != nil {
		t.Fatalf("find device for account-1: %v", err)
	}
	deviceTwo, err := store.FindDevice(context.Background(), "account-2", "shared-device")
	if err != nil {
		t.Fatalf("find device for account-2: %v", err)
	}

	if deviceOne.DeviceLabel == deviceTwo.DeviceLabel {
		t.Fatalf("expected isolated device labels, got %#v and %#v", deviceOne, deviceTwo)
	}
}

func TestSchemaReadyReflectsMigrationState(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	ready, err := store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("schema ready before migrations: %v", err)
	}
	if ready {
		t.Fatal("expected schema to be uninitialized before migrations")
	}

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	ready, err = store.SchemaReady(context.Background())
	if err != nil {
		t.Fatalf("schema ready after migrations: %v", err)
	}
	if !ready {
		t.Fatal("expected schema to be initialized after migrations")
	}
}
