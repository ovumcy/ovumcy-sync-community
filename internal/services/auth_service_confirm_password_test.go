package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConfirmCurrentPassword(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	ctx := context.Background()

	registered, err := auth.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := auth.ConfirmCurrentPassword(ctx, registered.AccountID, "correct horse battery staple"); err != nil {
		t.Fatalf("expected the right password to confirm, got %v", err)
	}
	for _, wrong := range []string{"wrong password here", ""} {
		if err := auth.ConfirmCurrentPassword(ctx, registered.AccountID, wrong); err != ErrInvalidCurrentPassword {
			t.Fatalf("expected ErrInvalidCurrentPassword for %q, got %v", wrong, err)
		}
	}
	if err := auth.ConfirmCurrentPassword(ctx, "missing-account", "any"); err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for an unknown account, got %v", err)
	}
}

// Managed accounts carry no password; their sessions come only from the
// managed bridge, so the step-up must not lock them out.
func TestConfirmCurrentPasswordPassesManagedAccount(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	bridge := NewManagedBridgeService(store, auth)
	ctx := context.Background()

	session, err := bridge.CreateManagedSession(ctx, "managedacct1234")
	if err != nil {
		t.Fatalf("create managed session: %v", err)
	}
	if err := auth.ConfirmCurrentPassword(ctx, session.AccountID, ""); err != nil {
		t.Fatalf("expected a managed account to pass, got %v", err)
	}
}

func TestConfirmCurrentPasswordSurfacesStoreError(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err := auth.ConfirmCurrentPassword(context.Background(), "any-account", "any")
	if err == nil || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected a store-failure error, got %v", err)
	}
}
