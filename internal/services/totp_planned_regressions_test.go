package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// TestAADForTOTPSecretPinsTheExactProductionString locks the at-rest
// encryption contract byte for byte. Every other TOTP test builds its AAD
// through aadForTOTPSecret itself, so a drive-by edit of the constant would
// re-encrypt consistently and stay green — this literal is the tripwire:
// changing the production AAD string silently invalidates every stored TOTP
// secret (SECURITY.md, formerly a planned regression).
func TestAADForTOTPSecretPinsTheExactProductionString(t *testing.T) {
	got := string(aadForTOTPSecret("account-123"))
	want := "ovumcy.sync-community.field.totp_secret:account-123"
	if got != want {
		t.Fatalf("TOTP AAD drifted from the production contract: got %q want %q", got, want)
	}
}

// TestVerifyChallengeRejectsAnExpiredChallenge pins TOTPChallengeTTL with an
// advancing injected clock: one second past expiry, a challenge is rejected
// as ErrTOTPChallengeInvalid even when the presented code is valid for the
// new time — expiry alone is terminal (SECURITY.md, formerly a planned
// regression).
func TestVerifyChallengeRejectsAnExpiredChallenge(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()

	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	challengeID, expiresAt, err := totp.IssueChallenge(ctx, accountID)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if want := now.UTC().Add(TOTPChallengeTTL); !expiresAt.Equal(want) {
		t.Fatalf("expected the challenge to expire at now+TTL (%v), got %v", want, expiresAt)
	}

	// One second past the TTL, with a code freshly valid for that later
	// instant, so only expiry can be the reason for rejection.
	later := now.Add(TOTPChallengeTTL + time.Second)
	totp.now = func() time.Time { return later }
	code := security.GenerateTOTPCode(secret, later.UTC().Unix()/security.TOTPStepSeconds)

	if _, err := totp.VerifyChallenge(ctx, challengeID, code); !errors.Is(err, ErrTOTPChallengeInvalid) {
		t.Fatalf("expected ErrTOTPChallengeInvalid for an expired challenge, got %v", err)
	}
}
