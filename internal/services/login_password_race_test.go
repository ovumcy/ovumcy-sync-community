package services

import (
	"context"
	"errors"
	"testing"

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
