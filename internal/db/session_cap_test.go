package db

import (
	"context"
	"errors"
	"fmt"
	gosync "sync"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

const testMaxSessions = 10

func accountSessionHashes(t *testing.T, store *Store, accountID string) map[string]bool {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), `SELECT token_hash FROM sessions WHERE account_id = ?`, accountID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	hashes := map[string]bool{}
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			t.Fatalf("scan session: %v", err)
		}
		hashes[hash] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate sessions: %v", err)
	}
	return hashes
}

// seedAgedSessions stores count sessions for accountID, the i-th created
// i seconds after base, with token hashes prefix0..prefix{count-1}.
func seedAgedSessions(t *testing.T, store *Store, accountID, prefix string, base time.Time, count int) {
	t.Helper()
	for i := range count {
		session := guardSession(accountID, fmt.Sprintf("%s%d", prefix, i))
		session.CreatedAt = base.Add(time.Duration(i) * time.Second)
		if _, err := store.CreateSession(context.Background(), session); err != nil {
			t.Fatalf("seed session %d: %v", i, err)
		}
	}
}

func seedManagedGuardAccount(t *testing.T, store *Store, accountID string) {
	t.Helper()
	if _, err := store.UpsertManagedAccount(context.Background(), models.Account{
		ID:            accountID,
		Login:         "managed:" + accountID,
		PasswordHash:  "managed_service_only",
		Mode:          "managed",
		PremiumActive: true,
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert managed account: %v", err)
	}
}

func TestMintPastMaxSessionsRevokesTheOldestOfThatAccountOnly(t *testing.T) {
	const maxSessions = 3
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		seed func(t *testing.T, store *Store, accountID string)
		mint func(store *Store, session models.Session) error
	}{
		{
			name: "verified password",
			seed: seedGuardAccount,
			mint: func(store *Store, session models.Session) error {
				return store.CreateSessionForVerifiedPassword(ctx, session, "verified-hash", maxSessions)
			},
		},
		{
			name: "totp challenge",
			seed: func(t *testing.T, store *Store, accountID string) {
				seedGuardAccount(t, store, accountID)
				if err := store.UpsertTOTPChallenge(ctx, guardChallenge(accountID, "challenge")); err != nil {
					t.Fatalf("seed challenge: %v", err)
				}
			},
			mint: func(store *Store, session models.Session) error {
				return store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", session, maxSessions)
			},
		},
		{
			name: "managed bridge",
			seed: seedManagedGuardAccount,
			mint: func(store *Store, session models.Session) error {
				return store.CreateSessionForUnlapsedManagedAccount(ctx, session, maxSessions)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			tc.seed(t, store, "capacct000001")
			seedGuardAccount(t, store, "otheracct0001")
			base := time.Now().UTC().Add(-time.Hour)
			seedAgedSessions(t, store, "capacct000001", "mine-", base, maxSessions)
			seedAgedSessions(t, store, "otheracct0001", "other-", base.Add(-time.Hour), maxSessions)

			if err := tc.mint(store, guardSession("capacct000001", "fresh")); err != nil {
				t.Fatalf("mint past the cap: %v", err)
			}

			got := accountSessionHashes(t, store, "capacct000001")
			want := map[string]bool{"mine-1": true, "mine-2": true, "fresh": true}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("expected the oldest session revoked, kept %v", got)
			}
			if got := accountSessionHashes(t, store, "otheracct0001"); len(got) != maxSessions {
				t.Fatalf("expected another account's older sessions untouched, kept %v", got)
			}
		})
	}
}

func TestMintUnderMaxSessionsRevokesNothing(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")
	seedAgedSessions(t, store, "guard-account", "s-", time.Now().UTC().Add(-time.Hour), 2)

	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-account", "fresh"), "verified-hash", 3); err != nil {
		t.Fatalf("mint at the cap: %v", err)
	}
	if got := accountSessionHashes(t, store, "guard-account"); len(got) != 3 {
		t.Fatalf("expected all three sessions kept, got %v", got)
	}
}

// A mint whose created_at sorts before every live session (a clock stepped
// back) must still keep the session it just returned to the caller.
func TestMintPastMaxSessionsNeverRevokesTheFreshSession(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")
	seedAgedSessions(t, store, "guard-account", "s-", time.Now().UTC(), 2)

	fresh := guardSession("guard-account", "fresh")
	fresh.CreatedAt = fresh.CreatedAt.Add(-24 * time.Hour)
	if err := store.CreateSessionForVerifiedPassword(ctx, fresh, "verified-hash", 2); err != nil {
		t.Fatalf("mint: %v", err)
	}
	got := accountSessionHashes(t, store, "guard-account")
	want := map[string]bool{"s-1": true, "fresh": true}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("expected the fresh session and the newest other kept, got %v", got)
	}
}

func TestMintRefusesANonPositiveMaxSessions(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")

	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-account", "fresh"), "verified-hash", 0); !errors.Is(err, ErrInvalidMaxSessions) {
		t.Fatalf("expected ErrInvalidMaxSessions, got %v", err)
	}
	if got := accountSessionHashes(t, store, "guard-account"); len(got) != 0 {
		t.Fatalf("expected nothing stored, got %v", got)
	}
}

func TestConcurrentMintsNeverExceedMaxSessions(t *testing.T) {
	const maxSessions = 3
	store, _ := newFileBackedTestStore(t)
	seedGuardAccount(t, store, "guard-account")

	const fanout = 8
	results := make([]error, fanout)
	start := make(chan struct{})
	var wg gosync.WaitGroup
	for i := range fanout {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = store.CreateSessionForVerifiedPassword(
				context.Background(),
				guardSession("guard-account", fmt.Sprintf("racer-%02d", i)),
				"verified-hash",
				maxSessions,
			)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range results {
		if err != nil {
			t.Fatalf("racer %d: %v", i, err)
		}
	}
	if got := accountSessionHashes(t, store, "guard-account"); len(got) != maxSessions {
		t.Fatalf("expected exactly %d live sessions after %d concurrent mints, got %d", maxSessions, fanout, len(got))
	}
}
