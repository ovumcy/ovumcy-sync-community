package services

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// These tests cover the transparent bcrypt-cost upgrade on login: accounts
// whose stored hash predates a cost bump verify at their old embedded cost,
// which is timing-distinguishable from the current-cost equalization
// placeholder on unknown-login paths (CWE-208). A successful login must
// therefore re-hash the password at the current cost — best-effort, never at
// the expense of the login itself.

func seedLegacyPasswordHash(t *testing.T, store *db.Store, accountID string, password string) string {
	t.Helper()

	legacyHash, err := bcrypt.GenerateFromPassword([]byte(password), security.PasswordHashCost-2)
	if err != nil {
		t.Fatalf("generate legacy hash: %v", err)
	}
	if err := store.UpdateAccountPasswordHash(context.Background(), accountID, string(legacyHash)); err != nil {
		t.Fatalf("seed legacy hash: %v", err)
	}
	return string(legacyHash)
}

func TestLoginRehashesLegacyLowerCostHash(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	ctx := context.Background()

	const password = "correct horse battery staple"
	registerResult, err := service.Register(ctx, "legacy@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	seedLegacyPasswordHash(t, store, registerResult.AccountID, password)

	loginResult, err := service.Login(ctx, "legacy@example.com", password)
	if err != nil {
		t.Fatalf("login with legacy-cost hash: %v", err)
	}
	if loginResult.SessionToken == "" {
		t.Fatal("expected a session token from the legacy-hash login")
	}

	account, err := store.FindAccountByLogin(ctx, "legacy@example.com")
	if err != nil {
		t.Fatalf("reload account: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(account.PasswordHash))
	if err != nil {
		t.Fatalf("parse upgraded hash cost: %v", err)
	}
	if cost != security.PasswordHashCost {
		t.Fatalf("expected stored hash upgraded to cost %d, got %d", security.PasswordHashCost, cost)
	}
	if err := security.ComparePasswordHash(account.PasswordHash, password); err != nil {
		t.Fatalf("upgraded hash must still verify the same password: %v", err)
	}

	// A second login finds nothing left to upgrade and still succeeds.
	if _, err := service.Login(ctx, "legacy@example.com", password); err != nil {
		t.Fatalf("second login after the upgrade: %v", err)
	}
}

// TestLoginRehashesLegacyHashOnTOTPChallengePath proves the upgrade also runs
// when password verification succeeds but login answers with a TOTP challenge
// instead of a session — the password was correct on that path too, and it is
// the only moment the server can observe it.
func TestLoginRehashesLegacyHashOnTOTPChallengePath(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totpService := NewTOTPService(store, authService, key, "ovumcy-sync-community-test")
	authService.AttachTOTPChallengeIssuer(totpService)

	ctx := context.Background()
	const password = "correct horse battery staple"
	registered, err := authService.Register(ctx, "legacy2fa@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	start, err := totpService.StartEnrollment(ctx, registered.AccountID, password)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	enrollStep := time.Now().UTC().Unix() / security.TOTPStepSeconds
	if err := totpService.CompleteEnrollment(
		ctx,
		registered.AccountID,
		security.HashToken(registered.SessionToken),
		security.GenerateTOTPCode(secret, enrollStep),
	); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	seedLegacyPasswordHash(t, store, registered.AccountID, password)

	loginResult, err := authService.Login(ctx, "legacy2fa@example.com", password)
	if err != nil {
		t.Fatalf("login with legacy-cost hash on TOTP account: %v", err)
	}
	if loginResult.TOTPChallenge == nil {
		t.Fatal("expected a TOTP challenge for the enrolled account")
	}
	if loginResult.SessionToken != "" {
		t.Fatal("a TOTP challenge response must not carry a session token")
	}

	account, err := store.FindAccountByLogin(ctx, "legacy2fa@example.com")
	if err != nil {
		t.Fatalf("reload account: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(account.PasswordHash))
	if err != nil {
		t.Fatalf("parse upgraded hash cost: %v", err)
	}
	if cost != security.PasswordHashCost {
		t.Fatalf("expected stored hash upgraded to cost %d on the challenge path, got %d",
			security.PasswordHashCost, cost)
	}
}

// TestLoginSucceedsWhenRehashCannotProduceNewHash exercises the best-effort
// contract on a rehash failure: an account created before the current
// password-strength rule can hold a (correct) password shorter than today's
// minimum, so HashPassword refuses to re-hash it. The upgrade is skipped, the
// stored hash stays untouched, and — the actual invariant — the login still
// succeeds.
func TestLoginSucceedsWhenRehashCannotProduceNewHash(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	ctx := context.Background()

	// 10 characters: verifies against its stored hash, but below the 12-char
	// minimum HashPassword enforces, so the rehash attempt must fail cleanly.
	const shortLegacyPassword = "short pass"
	registerResult, err := service.Register(ctx, "oldtimer@example.com", "temporary password 123")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	legacyHash := seedLegacyPasswordHash(t, store, registerResult.AccountID, shortLegacyPassword)

	loginResult, err := service.Login(ctx, "oldtimer@example.com", shortLegacyPassword)
	if err != nil {
		t.Fatalf("login must succeed even though the rehash cannot run: %v", err)
	}
	if loginResult.SessionToken == "" {
		t.Fatal("expected a session token despite the skipped rehash")
	}

	account, err := store.FindAccountByLogin(ctx, "oldtimer@example.com")
	if err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if account.PasswordHash != legacyHash {
		t.Fatal("stored hash must remain unchanged when the rehash is skipped")
	}
}
