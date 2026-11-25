package db

import (
	"context"
	"strings"
	"testing"
)

func TestSessionInsertGuardsSurfaceStoreErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("verified-password insert, sessions dropped", func(t *testing.T) {
		store, dbPath := newFileBackedTestStore(t)
		seedGuardAccount(t, store, "guard-errors")
		dropTable(t, dbPath, "sessions")
		err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-errors", "s"), "verified-hash", testMaxSessions)
		if err == nil || !strings.Contains(err.Error(), "insert session for verified password") {
			t.Fatalf("expected the insert error, got %v", err)
		}
	})

	t.Run("consume, totp_challenges dropped", func(t *testing.T) {
		store, dbPath := newFileBackedTestStore(t)
		seedGuardAccount(t, store, "guard-errors")
		dropTable(t, dbPath, "totp_challenges")
		err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "c", guardSession("guard-errors", "s"), testMaxSessions)
		if err == nil || !strings.Contains(err.Error(), "consume totp challenge") {
			t.Fatalf("expected the challenge delete error, got %v", err)
		}
	})

	t.Run("consume, store closed", func(t *testing.T) {
		store, _ := newFileBackedTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "c", guardSession("guard-errors", "s"), testMaxSessions)
		if err == nil || !strings.Contains(err.Error(), "begin consume totp challenge") {
			t.Fatalf("expected the begin error, got %v", err)
		}
	})
}
