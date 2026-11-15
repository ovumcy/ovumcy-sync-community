package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

const changePasswordWindowNewPassword = "new staple battery horse correct"

// A password change on an enrolled account spends the same per-account window
// as every other code check, so it is no extra code oracle.
func TestChangePasswordSharesTheAccountTOTPWindow(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)
	sessionHash := security.HashToken(token)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong := wrongTOTPCode(t, secret, later)
	for range maxTOTPAccountFailedAttempts {
		if _, err := auth.ChangePassword(ctx, accountID, sessionHash, totpWindowTestPassword, changePasswordWindowNewPassword, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode, got %v", err)
		}
	}

	correct := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	if _, err := auth.ChangePassword(ctx, accountID, sessionHash, totpWindowTestPassword, changePasswordWindowNewPassword, correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected the change to be locked, got %v", err)
	}
	if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: sessionHash, CurrentPassword: totpWindowTestPassword}, correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected regeneration to share the lock, got %v", err)
	}
}

// A missing code (an old client) stops before the window.
func TestChangePasswordMissingCodeSpendsNoTOTPAttempt(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)
	sessionHash := security.HashToken(token)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	for range maxTOTPAccountFailedAttempts {
		if _, err := auth.ChangePassword(ctx, accountID, sessionHash, totpWindowTestPassword, changePasswordWindowNewPassword, ""); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode for a missing code, got %v", err)
		}
	}

	correct := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	if _, err := auth.ChangePassword(ctx, accountID, sessionHash, totpWindowTestPassword, changePasswordWindowNewPassword, correct); err != nil {
		t.Fatalf("expected the correct code to work after a window of missing codes, got %v", err)
	}
}

// A code already spent on another step-up cannot be replayed on a change.
func TestChangePasswordRefusesAReplayedCode(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	code := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(token), CurrentPassword: totpWindowTestPassword}, code); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if _, err := auth.ChangePassword(ctx, accountID, security.HashToken(token), totpWindowTestPassword, changePasswordWindowNewPassword, code); !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected ErrTOTPReplayed, got %v", err)
	}
}
