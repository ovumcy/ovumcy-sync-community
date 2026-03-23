package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestAccountRepositoryConflictAndLookups(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	account := models.Account{
		ID:            "account-1",
		Login:         "owner@example.com",
		PasswordHash:  "hash",
		Mode:          "self_hosted",
		PremiumActive: false,
		CreatedAt:     now,
	}
	if _, err := store.CreateAccount(context.Background(), account); err != nil {
		t.Fatalf("create account: %v", err)
	}

	if _, err := store.CreateAccount(context.Background(), account); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	foundByLogin, err := store.FindAccountByLogin(context.Background(), account.Login)
	if err != nil {
		t.Fatalf("find account by login: %v", err)
	}
	if foundByLogin.ID != account.ID {
		t.Fatalf("unexpected account lookup result: %#v", foundByLogin)
	}

	if _, err := store.FindAccountByID(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account id, got %v", err)
	}
	if _, err := store.FindAccountByLogin(context.Background(), "missing@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing login, got %v", err)
	}
}

func TestManagedAccountUpsertPreservesIdentityAndUpdatesFlags(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	created, err := store.UpsertManagedAccount(context.Background(), models.Account{
		ID:            "managedacct1234",
		Login:         "managed:managedacct1234",
		PasswordHash:  "managed_service_only",
		Mode:          "managed",
		PremiumActive: true,
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}

	updatedAt := now.Add(2 * time.Hour)
	if _, err := store.UpsertManagedAccount(context.Background(), models.Account{
		ID:            created.ID,
		Login:         "managed:managedacct1234",
		PasswordHash:  "rotated_hash",
		Mode:          "managed",
		PremiumActive: false,
		CreatedAt:     updatedAt,
	}); err != nil {
		t.Fatalf("update managed account: %v", err)
	}

	account, err := store.FindAccountByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("find managed account: %v", err)
	}
	if account.PasswordHash != "rotated_hash" || account.PremiumActive {
		t.Fatalf("unexpected managed account flags after upsert: %#v", account)
	}
}

func TestSessionRepositoryLifecycleAndNotFound(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	if _, err := store.CreateAccount(context.Background(), models.Account{
		ID:           "account-1",
		Login:        "owner@example.com",
		PasswordHash: "hash",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}

	session := models.Session{
		ID:         "session-1",
		AccountID:  "account-1",
		TokenHash:  "token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	if _, err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	lastSeenAt := now.Add(time.Hour)
	if err := store.TouchSession(context.Background(), session.ID, lastSeenAt); err != nil {
		t.Fatalf("touch session: %v", err)
	}

	touched, err := store.FindSessionByTokenHash(context.Background(), session.TokenHash)
	if err != nil {
		t.Fatalf("find touched session: %v", err)
	}
	if !touched.LastSeenAt.Equal(lastSeenAt) {
		t.Fatalf("expected updated last seen time, got %#v", touched)
	}

	if err := store.DeleteSessionByTokenHash(context.Background(), session.TokenHash); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	if _, err := store.FindSessionByTokenHash(context.Background(), session.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := store.TouchSession(context.Background(), "missing-session", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing touch, got %v", err)
	}
	if err := store.DeleteSessionByTokenHash(context.Background(), "missing-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing delete, got %v", err)
	}
}

func TestBlobAndRecoveryRepositoriesReturnNotFoundBeforeWrite(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.GetEncryptedBlob(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing blob, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing recovery package, got %v", err)
	}
}
