package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func seedChangePasswordSession(t *testing.T, store *Store, accountID, tokenHash string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := store.CreateSession(context.Background(), models.Session{
		ID:         tokenHash + "-id",
		AccountID:  accountID,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func TestChangeAccountPasswordGuards(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	seedFaultInjectionAccount(t, store, "account-target")
	seedChangePasswordSession(t, store, "account-target", "caller")
	seedChangePasswordSession(t, store, "account-target", "other")

	if err := store.ChangeAccountPassword(ctx, "account-target", "stale", "new-hash", "caller"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for a moved hash, got %v", err)
	}
	if err := store.ChangeAccountPassword(ctx, "account-target", "hash", "new-hash", "revoked"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing caller session, got %v", err)
	}
	if err := store.ChangeAccountPassword(ctx, "missing", "hash", "new-hash", "caller"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing account, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "other"); err != nil {
		t.Fatalf("a refused change must not revoke sessions: %v", err)
	}

	if err := store.ChangeAccountPassword(ctx, "account-target", "hash", "new-hash", "caller"); err != nil {
		t.Fatalf("change: %v", err)
	}
	account, err := store.FindAccountByID(ctx, "account-target")
	if err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if account.PasswordHash != "new-hash" {
		t.Fatalf("expected the new hash, got %q", account.PasswordHash)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "caller"); err != nil {
		t.Fatalf("expected the caller's session kept: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the other session revoked, got %v", err)
	}
}

func TestChangeAccountPasswordSurfacesStoreFailures(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		err := store.ChangeAccountPassword(context.Background(), "account-target", "hash", "new-hash", "caller")
		if err == nil || !strings.Contains(err.Error(), "begin change account password") {
			t.Fatalf("expected the begin error, got %v", err)
		}
	})

	t.Run("accounts table dropped", func(t *testing.T) {
		store, dbPath := newFileBackedTestStore(t)
		seedFaultInjectionAccount(t, store, "account-target")
		dropTable(t, dbPath, "accounts")
		err := store.ChangeAccountPassword(context.Background(), "account-target", "hash", "new-hash", "caller")
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			t.Fatalf("expected a store failure, got %v", err)
		}
	})
}
