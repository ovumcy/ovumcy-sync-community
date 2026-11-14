package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// TestLoginRacingAPasswordChangeIssuesNoTOTPChallenge lands a password change
// between the login's verify and its challenge insert (via the rehash hook):
// the challenge must not be stored, or it would complete into a session that
// outlives the change.
func TestLoginRacingAPasswordChangeIssuesNoTOTPChallenge(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, _, _ := enrollTOTP(t, auth, totp, now)
	const password = "correct horse battery staple"
	seedLegacyPasswordHash(t, auth.store, accountID, password)

	changedHash, err := security.HashPassword("a freshly changed passphrase")
	if err != nil {
		t.Fatalf("hash new password: %v", err)
	}
	auth.hashPassword = func(string) (string, error) {
		if err := auth.store.UpdateAccountPasswordHash(ctx, accountID, changedHash); err != nil {
			t.Fatalf("concurrent password change: %v", err)
		}
		return "", errors.New("rehash skipped")
	}

	result, err := auth.Login(ctx, "owner@example.com", password)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v (result %+v)", err, result)
	}
	if result.TOTPChallenge != nil || result.SessionToken != "" {
		t.Fatalf("expected neither a challenge nor a session, got %+v", result)
	}
}

// TestConcurrentLegacyLoginsBothGetSessions: two honest logins on a legacy
// hash both rehash; the CAS loser's verified hash is stale, so its insert
// misses and it must verify again rather than answer 401.
func TestConcurrentLegacyLoginsBothGetSessions(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, time.Hour)
	ctx := context.Background()
	const password = "correct horse battery staple"
	registered, err := auth.Register(ctx, "twins@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	legacyHash := seedLegacyPasswordHash(t, store, registered.AccountID, password)

	auth.hashPassword = func(p string) (string, error) {
		winnerHash, err := security.HashPassword(p)
		if err != nil {
			return "", err
		}
		if err := store.UpgradeAccountPasswordHash(ctx, registered.AccountID, legacyHash, winnerHash); err != nil {
			t.Fatalf("concurrent winner's upgrade: %v", err)
		}
		return security.HashPassword(p)
	}

	result, err := auth.Login(ctx, "twins@example.com", password)
	if err != nil || result.SessionToken == "" {
		t.Fatalf("the CAS loser must still get a session: %+v, %v", result, err)
	}
}

// TestLoginRacingTOTPEnrollmentGetsAChallengeNotASession: enrollment
// completing between the verify and the insert must not leave a
// password-only session; the retried login sees TOTP and returns a challenge.
func TestLoginRacingTOTPEnrollmentGetsAChallengeNotASession(t *testing.T) {
	auth, _, _ := fixedTOTPClock(t)
	ctx := context.Background()
	const password = "correct horse battery staple"
	registered, err := auth.Register(ctx, "enroller@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	seedLegacyPasswordHash(t, auth.store, registered.AccountID, password)

	auth.hashPassword = func(string) (string, error) {
		if err := auth.store.UpdateTOTPSecretAndEnabled(ctx, registered.AccountID, "enrolled-secret-ciphertext", true); err != nil {
			t.Fatalf("concurrent enrollment: %v", err)
		}
		return "", errors.New("rehash skipped")
	}

	result, err := auth.Login(ctx, "enroller@example.com", password)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.SessionToken != "" || result.TOTPChallenge == nil {
		t.Fatalf("expected a challenge and no session, got %+v", result)
	}
}

// TestSessionFromAConsumedChallengeIsRefused drives the session step of
// VerifyChallenge twice on one challenge — what two verifies racing with
// adjacent-step codes, or a verify racing a password change, reach — and
// expects exactly one session.
func TestSessionFromAConsumedChallengeIsRefused(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, _, _ := enrollTOTP(t, auth, totp, now)

	challengeID, _, err := totp.IssueChallenge(ctx, accountID)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	first, err := auth.createSessionConsumingChallenge(ctx, accountID, security.HashToken(challengeID))
	if err != nil || first.SessionToken == "" {
		t.Fatalf("first consume: %+v, %v", first, err)
	}
	if _, err := auth.createSessionConsumingChallenge(ctx, accountID, security.HashToken(challengeID)); !errors.Is(err, ErrTOTPChallengeInvalid) {
		t.Fatalf("expected ErrTOTPChallengeInvalid on a consumed challenge, got %v", err)
	}
}
