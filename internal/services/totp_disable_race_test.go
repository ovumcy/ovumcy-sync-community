package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// TestDisableRacingAStateChangeChangesNothing lands a concurrent change
// between Disable's password/secret read and its write (via the clock hook
// verifyAccountCode calls): the disable must not commit, and its error names
// what moved.
func TestDisableRacingAStateChangeChangesNothing(t *testing.T) {
	const password = "correct horse battery staple"
	cases := []struct {
		name       string
		race       func(t *testing.T, auth *AuthService, accountID string)
		want       error
		wantTOTPOn bool
	}{
		{
			name: "password changed",
			race: func(t *testing.T, auth *AuthService, accountID string) {
				changed, err := security.HashPassword("a freshly changed passphrase")
				if err != nil {
					t.Fatalf("hash new password: %v", err)
				}
				if err := auth.store.UpdateAccountPasswordHash(context.Background(), accountID, changed); err != nil {
					t.Fatalf("concurrent password change: %v", err)
				}
			},
			want:         ErrInvalidCurrentPassword,
			wantTOTPOn:   true,
		},
		{
			name: "already disabled",
			race: func(t *testing.T, auth *AuthService, accountID string) {
				if err := auth.store.UpdateTOTPSecretAndEnabled(context.Background(), accountID, "", false); err != nil {
					t.Fatalf("concurrent disable: %v", err)
				}
			},
			want:         ErrTOTPNotConfigured,
			wantTOTPOn:   false,
		},
		{
			name: "re-enrolled with a new secret",
			race: func(t *testing.T, auth *AuthService, accountID string) {
				if err := auth.store.UpdateTOTPSecretAndEnabled(context.Background(), accountID, "re-enrolled-ciphertext", true); err != nil {
					t.Fatalf("concurrent re-enroll: %v", err)
				}
			},
			want:         ErrTOTPInvalidCode,
			wantTOTPOn:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth, totp, now := fixedTOTPClock(t)
			ctx := context.Background()
			accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)

			disableNow := now.Add(security.TOTPStepSeconds * time.Second)
			raced := false
			totp.now = func() time.Time {
				if !raced {
					raced = true
					tc.race(t, auth, accountID)
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
			if account.TOTPEnabled != tc.wantTOTPOn {
				t.Fatalf("expected totp_enabled=%v after the raced disable, got %v", tc.wantTOTPOn, account.TOTPEnabled)
			}
			if _, err := auth.Authenticate(ctx, token); err != nil {
				t.Fatalf("expected the session kept, got %v", err)
			}
		})
	}
}
