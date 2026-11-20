package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// TestDisableRacingAStateChange lands a concurrent change between Disable's
// password/secret read and its write (via the clock hook verifyAccountCode
// calls). A change that moved the credentials must leave the account exactly
// as the race left it — TOTP, secret, session and pending challenge — and the
// error names what moved (a moved secret already loses the step claim, which
// is bound to the verified secret); a login rehash, which moves only the hash,
// must still let the disable through. Only the re-enrolled race keeps its
// step-up slot spent: losing to a concurrent disable is a state refusal (409),
// and the others pass the code check, whose success clears the budget.
func TestDisableRacingAStateChange(t *testing.T) {
	const password = "correct horse battery staple"
	ctx := context.Background()
	cases := []struct {
		name    string
		race    func(t *testing.T, store *db.Store, account models.Account)
		want    error
		charged bool
	}{
		{
			name: "password changed",
			race: func(t *testing.T, store *db.Store, account models.Account) {
				changed, err := security.HashPassword("a freshly changed passphrase")
				if err != nil {
					t.Fatalf("hash new password: %v", err)
				}
				if err := store.UpdateAccountPasswordHash(ctx, account.ID, changed); err != nil {
					t.Fatalf("concurrent password change: %v", err)
				}
			},
			want: ErrInvalidCurrentPassword,
		},
		{
			name: "already disabled",
			race: func(t *testing.T, store *db.Store, account models.Account) {
				if err := store.UpdateTOTPSecretAndEnabled(ctx, account.ID, "", false); err != nil {
					t.Fatalf("concurrent disable: %v", err)
				}
			},
			want: ErrTOTPNotEnabled,
		},
		{
			name: "re-enrolled with a new secret",
			race: func(t *testing.T, store *db.Store, account models.Account) {
				if err := store.UpdateTOTPSecretAndEnabled(ctx, account.ID, "re-enrolled-ciphertext", true); err != nil {
					t.Fatalf("concurrent re-enroll: %v", err)
				}
			},
			want:    ErrTOTPReplayed,
			charged: true,
		},
		{
			name: "login rehash",
			race: func(t *testing.T, store *db.Store, account models.Account) {
				rehashed, err := security.HashPassword(password)
				if err != nil {
					t.Fatalf("rehash password: %v", err)
				}
				if err := store.UpgradeAccountPasswordHash(ctx, account.ID, account.PasswordHash, rehashed); err != nil {
					t.Fatalf("concurrent rehash: %v", err)
				}
			},
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth, totp, now := fixedTOTPClock(t)
			accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)
			seedAccount, err := auth.store.FindAccountByID(ctx, accountID)
			if err != nil {
				t.Fatalf("find account: %v", err)
			}
			if err := auth.store.CreateTOTPChallengeForVerifiedPassword(ctx, models.TOTPChallenge{
				ChallengeIDHash: "pending-challenge",
				AccountID:       accountID,
				CreatedAt:       now,
				ExpiresAt:       now.Add(TOTPChallengeTTL),
			}, seedAccount.PasswordHash); err != nil {
				t.Fatalf("seed challenge: %v", err)
			}

			disableNow := now.Add(security.TOTPStepSeconds * time.Second)
			var afterRace models.Account
			raced := false
			totp.now = func() time.Time {
				if !raced {
					raced = true
					before, err := auth.store.FindAccountByID(ctx, accountID)
					if err != nil {
						t.Fatalf("find account: %v", err)
					}
					tc.race(t, auth.store, before)
					if afterRace, err = auth.store.FindAccountByID(ctx, accountID); err != nil {
						t.Fatalf("find account: %v", err)
					}
				}
				return disableNow
			}
			code := security.GenerateTOTPCode(secret, disableNow.Unix()/security.TOTPStepSeconds)

			if err := totp.Disable(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(token), CurrentPassword: password, TOTPCode: code}); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			account, err := auth.store.FindAccountByID(ctx, accountID)
			if err != nil {
				t.Fatalf("find account: %v", err)
			}
			_, sessionErr := auth.Authenticate(ctx, token)
			_, challengeErr := auth.store.FindTOTPChallengeByHash(ctx, "pending-challenge")

			stepUp := totp.budget(ctx, totpPurposeStepUp, accountID)
			totp.attempts.mu.Lock()
			clientSpent, accountSpent := totp.attempts.entries[stepUp.client].count, totp.attempts.entries[stepUp.account].count
			totp.attempts.mu.Unlock()
			want := 0
			if tc.charged {
				want = 1
			}
			if clientSpent != want || accountSpent != want {
				t.Fatalf("step-up slots spent: client %d, account %d, want %d each", clientSpent, accountSpent, want)
			}

			if tc.want == nil {
				if account.TOTPEnabled || account.TOTPSecretEncrypted != "" {
					t.Fatal("expected TOTP cleared")
				}
				if !errors.Is(sessionErr, ErrUnauthorized) || !errors.Is(challengeErr, db.ErrNotFound) {
					t.Fatalf("expected session and challenge removed, got %v / %v", sessionErr, challengeErr)
				}
				return
			}
			if account.TOTPEnabled != afterRace.TOTPEnabled || account.TOTPSecretEncrypted != afterRace.TOTPSecretEncrypted || account.PasswordHash != afterRace.PasswordHash {
				t.Fatal("expected the raced disable to change nothing")
			}
			if sessionErr != nil || challengeErr != nil {
				t.Fatalf("expected session and challenge kept, got %v / %v", sessionErr, challengeErr)
			}
		})
	}
}

// TestDisableRefusesACallerSessionRevokedMidRequest revokes the caller's
// session (a device removal, a logout) between Disable's checks and its write:
// the disable must change nothing and answer as for any revoked session.
func TestDisableRefusesACallerSessionRevokedMidRequest(t *testing.T) {
	const password = "correct horse battery staple"
	ctx := context.Background()
	auth, totp, now := fixedTOTPClock(t)
	accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)

	disableNow := now.Add(security.TOTPStepSeconds * time.Second)
	revoked := false
	totp.now = func() time.Time {
		if !revoked {
			revoked = true
			if err := auth.store.DeleteSessionByTokenHash(ctx, security.HashToken(token)); err != nil {
				t.Fatalf("revoke session: %v", err)
			}
		}
		return disableNow
	}
	code := security.GenerateTOTPCode(secret, disableNow.Unix()/security.TOTPStepSeconds)

	err := totp.Disable(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(token), CurrentPassword: password, TOTPCode: code})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
	account, err := auth.store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if !account.TOTPEnabled || account.TOTPSecretEncrypted == "" {
		t.Fatal("expected TOTP kept for a revoked caller")
	}
}
