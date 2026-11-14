package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

func fileBackedTOTPServices(t *testing.T) (auth *AuthService, totp *TOTPService, dbPath string, now time.Time) {
	t.Helper()
	store, path := openFileBackedTestStore(t)
	auth = NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp = NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)
	now = time.Date(2026, 7, 7, 10, 0, 5, 0, time.UTC)
	auth.now = func() time.Time { return now }
	totp.now = func() time.Time { return now }
	return auth, totp, path, now
}

// TestLoginWhoseStateMovesTwiceIsRefused: a login whose verified hash goes
// stale on both attempts answers the generic invalid-credentials error
// rather than looping.
func TestLoginWhoseStateMovesTwiceIsRefused(t *testing.T) {
	auth := NewAuthService(openTestStore(t), 24*time.Hour)
	ctx := context.Background()
	const password = "correct horse battery staple"
	registered, err := auth.Register(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	seedLegacyPasswordHash(t, auth.store, registered.AccountID, password)

	moves := 0
	auth.hashPassword = func(string) (string, error) {
		moves++
		seedLegacyPasswordHash(t, auth.store, registered.AccountID, password)
		return "", errors.New("rehash skipped")
	}

	result, err := auth.Login(ctx, "owner@example.com", password)
	if !errors.Is(err, ErrInvalidCredentials) || result.SessionToken != "" {
		t.Fatalf("expected ErrInvalidCredentials and no session, got %+v, %v", result, err)
	}
	if moves != 2 {
		t.Fatalf("expected exactly one retry (2 attempts), got %d", moves)
	}
}

func TestLoginSurfacesASessionInsertStoreError(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	ctx := context.Background()
	if _, err := auth.Register(ctx, "owner@example.com", "correct horse battery staple"); err != nil {
		t.Fatalf("register: %v", err)
	}
	dropTable(t, dbPath, "sessions")

	_, err := auth.Login(ctx, "owner@example.com", "correct horse battery staple")
	if err == nil || !strings.Contains(err.Error(), "insert session for verified password") {
		t.Fatalf("expected the session insert store error, got %v", err)
	}
}

func TestVerifyChallengeSurfacesASessionInsertStoreError(t *testing.T) {
	auth, totp, dbPath, now := fileBackedTOTPServices(t)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)
	challengeID, _, err := totp.IssueChallenge(ctx, accountID)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	dropTable(t, dbPath, "sessions")

	verifyNow := now.Add(security.TOTPStepSeconds * time.Second)
	totp.now = func() time.Time { return verifyNow }
	code := security.GenerateTOTPCode(secret, verifyNow.Unix()/security.TOTPStepSeconds)
	if _, err := totp.VerifyChallenge(ctx, challengeID, code); err == nil || !strings.Contains(err.Error(), "insert session for totp challenge") {
		t.Fatalf("expected the session insert store error, got %v", err)
	}
}

// TestVerifyChallengeLosingItsChallengeMidwayIsInvalid deletes the challenge
// after VerifyChallenge has read it (via the clock hook), as a concurrent
// verify or password change would: no session, ErrTOTPChallengeInvalid.
func TestVerifyChallengeLosingItsChallengeMidwayIsInvalid(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)
	challengeID, _, err := totp.IssueChallenge(ctx, accountID)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	verifyNow := now.Add(security.TOTPStepSeconds * time.Second)
	deleted := false
	totp.now = func() time.Time {
		if !deleted {
			deleted = true
			if err := auth.store.DeleteTOTPChallengeByHash(ctx, security.HashToken(challengeID)); err != nil {
				t.Fatalf("concurrent challenge delete: %v", err)
			}
		}
		return verifyNow
	}
	code := security.GenerateTOTPCode(secret, verifyNow.Unix()/security.TOTPStepSeconds)
	result, err := totp.VerifyChallenge(ctx, challengeID, code)
	if !errors.Is(err, ErrTOTPChallengeInvalid) || result.SessionToken != "" {
		t.Fatalf("expected ErrTOTPChallengeInvalid and no session, got %+v, %v", result, err)
	}
}
