package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// A session-authenticated write whose body arrives after the caller's session
// was revoked (a password change or reset, a TOTP change, a device removal
// elsewhere) must change nothing and answer as unauthenticated.
func TestLateBodyWritesFromARevokedSessionChangeNothing(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp := NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	ctx := context.Background()

	registered, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	other, err := auth.Login(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := syncService.AttachDeviceForSession(ctx, registered.AccountID, security.HashToken(other.SessionToken), "device-a", "phone"); err != nil {
		t.Fatalf("attach device: %v", err)
	}
	if err := auth.RevokeSession(ctx, registered.SessionToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked := ownerStepUp(registered)
	before, err := store.FindAccountByID(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}

	if _, err := auth.RegenerateRecoveryCode(ctx, registered.AccountID, revoked, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("regenerate: expected ErrUnauthorized, got %v", err)
	}
	if _, err := totp.StartEnrollment(ctx, registered.AccountID, revoked); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("enroll start: expected ErrUnauthorized, got %v", err)
	}
	if err := syncService.RemoveDevice(ctx, registered.AccountID, revoked.SessionTokenHash, "device-a"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("remove device: expected ErrUnauthorized, got %v", err)
	}
	ciphertext := []byte("ciphertext")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, registered.AccountID, revoked.SessionTokenHash, PutBlobInput{
		SchemaVersion: 1, Generation: 1, ChecksumSHA256: hex.EncodeToString(sum[:]), Ciphertext: ciphertext,
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("put blob: expected ErrUnauthorized, got %v", err)
	}
	if _, err := syncService.PutBlob(ctx, "missing-account", revoked.SessionTokenHash, PutBlobInput{
		SchemaVersion: 1, Generation: 1, ChecksumSHA256: hex.EncodeToString(sum[:]), Ciphertext: ciphertext,
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("put blob for a missing account: expected ErrUnauthorized, got %v", err)
	}

	after, err := store.FindAccountByID(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if after.RecoveryCodeHash != before.RecoveryCodeHash || after.TOTPSecretEncrypted != "" {
		t.Fatal("expected the revoked caller to change no credentials")
	}
	if _, err := store.FindDevice(ctx, registered.AccountID, "device-a"); err != nil {
		t.Fatalf("expected the device kept: %v", err)
	}
	if _, err := store.GetEncryptedBlob(ctx, registered.AccountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected no blob written, got %v", err)
	}
}

// An enrollment verified from a session revoked after the start must not
// enable TOTP or hand out a recovery code.
func TestCompleteEnrollmentFromARevokedSessionEnablesNothing(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp := NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)
	ctx := context.Background()

	registered, err := auth.Register(ctx, "owner@example.com", stepUpTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	start, err := totp.StartEnrollment(ctx, registered.AccountID, ownerStepUp(registered))
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if err := auth.RevokeSession(ctx, registered.SessionToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	recovery, err := totp.CompleteEnrollment(
		ctx,
		registered.AccountID,
		security.HashToken(registered.SessionToken),
		security.GenerateTOTPCode(secret, time.Now().UTC().Unix()/security.TOTPStepSeconds),
	)
	if !errors.Is(err, ErrUnauthorized) || recovery != "" {
		t.Fatalf("expected ErrUnauthorized and no recovery code, got %q, %v", recovery, err)
	}
	account, err := store.FindAccountByID(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled {
		t.Fatal("expected TOTP to stay off")
	}
}
