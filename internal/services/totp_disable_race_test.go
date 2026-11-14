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
// error names what moved; a login rehash, which moves only the hash, must
// still let the disable through.
func TestDisableRacingAStateChange(t *testing.T) {
	const password = "correct horse battery staple"
	ctx := context.Background()
	cases := []struct {
		name string
		race func(t *testing.T, store *db.Store, account models.Account)
		want error
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
			want: ErrTOTPNotConfigured,
		},
		{
			name: "re-enrolled with a new secret",
			race: func(t *testing.T, store *db.Store, account models.Account) {
				if err := store.UpdateTOTPSecretAndEnabled(ctx, account.ID, "re-enrolled-ciphertext", true); err != nil {
					t.Fatalf("concurrent re-enroll: %v", err)
				}
			},
			want: ErrTOTPInvalidCode,
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
			if err := auth.store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
				ChallengeIDHash: "pending-challenge",
				AccountID:       accountID,
				CreatedAt:       now,
				ExpiresAt:       now.Add(TOTPChallengeTTL),
			}); err != nil {
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

			if err := totp.Disable(ctx, accountID, password, code); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			account, err := auth.store.FindAccountByID(ctx, accountID)
			if err != nil {
				t.Fatalf("find account: %v", err)
			}
			_, sessionErr := auth.Authenticate(ctx, token)
			_, challengeErr := auth.store.FindTOTPChallengeByHash(ctx, "pending-challenge")

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
