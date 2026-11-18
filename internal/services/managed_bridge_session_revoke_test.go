package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRevokeManagedAccountSessionsRejectsInvalidAccountID(t *testing.T) {
	store := openTestStore(t)
	bridgeService := NewManagedBridgeService(store, NewAuthService(store, 24*time.Hour))

	for _, id := range []string{"bad", "invalid*chars!", ""} {
		if err := bridgeService.RevokeManagedAccountSessions(context.Background(), id); !errors.Is(err, ErrInvalidManagedAccount) {
			t.Fatalf("id %q: expected ErrInvalidManagedAccount, got %v", id, err)
		}
	}
}

func TestRevokeManagedAccountSessionsRevokesEverySessionOfTheManagedAccount(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)
	ctx := context.Background()

	var targetTokens []string
	for range 2 {
		minted, err := bridgeService.CreateManagedSession(ctx, "managedacct1234")
		if err != nil {
			t.Fatalf("mint managed session: %v", err)
		}
		targetTokens = append(targetTokens, minted.SessionToken)
	}
	bystander, err := bridgeService.CreateManagedSession(ctx, "managedbystander")
	if err != nil {
		t.Fatalf("mint bystander session: %v", err)
	}

	// The id is normalized like every other bridge route.
	if err := bridgeService.RevokeManagedAccountSessions(ctx, "  ManagedAcct1234 "); err != nil {
		t.Fatalf("revoke managed sessions: %v", err)
	}
	for _, token := range targetTokens {
		if _, err := authService.Authenticate(ctx, token); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("expected a revoked session refused with ErrUnauthorized, got %v", err)
		}
	}
	if _, err := authService.Authenticate(ctx, bystander.SessionToken); err != nil {
		t.Fatalf("expected the other managed account's session intact, got %v", err)
	}
	account, err := store.FindAccountByID(ctx, "managedacct1234")
	if err != nil || account.Mode != "managed" || !account.PremiumActive {
		t.Fatalf("expected the managed account row intact, got %+v err=%v", account, err)
	}

	// Safe to repeat, and the next mint issues a working session.
	if err := bridgeService.RevokeManagedAccountSessions(ctx, "managedacct1234"); err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	reminted, err := bridgeService.CreateManagedSession(ctx, "managedacct1234")
	if err != nil {
		t.Fatalf("mint after revoke: %v", err)
	}
	if _, err := authService.Authenticate(ctx, reminted.SessionToken); err != nil {
		t.Fatalf("expected a session minted after the revoke to authenticate, got %v", err)
	}
}

// TestRevokeManagedAccountSessionsAnswersASelfHostedIDLikeAnAbsentOne: the
// bridge credential learns nothing about a self-hosted account and changes
// nothing on it.
func TestRevokeManagedAccountSessionsAnswersASelfHostedIDLikeAnAbsentOne(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)
	ctx := context.Background()

	registered, err := authService.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !managedAccountIDPattern.MatchString(registered.AccountID) {
		t.Fatalf("self-hosted id %q does not pass the bridge id gate; the collision is not exercised", registered.AccountID)
	}

	absentErr := bridgeService.RevokeManagedAccountSessions(ctx, "neverexisted1234")
	selfHostedErr := bridgeService.RevokeManagedAccountSessions(ctx, registered.AccountID)
	if absentErr != nil || selfHostedErr != nil {
		t.Fatalf("expected nil for both an absent and a self-hosted id, got absent=%v self-hosted=%v", absentErr, selfHostedErr)
	}
	if _, err := authService.Authenticate(ctx, registered.SessionToken); err != nil {
		t.Fatalf("expected the self-hosted session to survive, got %v", err)
	}
}

func TestRevokeManagedAccountSessionsSurfacesAStoreFailure(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	bridgeService := NewManagedBridgeService(store, NewAuthService(store, 24*time.Hour))
	dropTable(t, dbPath, "sessions")

	err := bridgeService.RevokeManagedAccountSessions(context.Background(), "managedacct1234")
	if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected the store failure surfaced, got %v", err)
	}
}
