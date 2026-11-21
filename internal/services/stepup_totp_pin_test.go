package services

import (
	"context"
	"errors"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// midStepUpVerifier accepts any code after running during, which stands in
// for a change the same session commits while the step-up is being checked.
type midStepUpVerifier struct {
	during func(account models.Account)
}

func (v midStepUpVerifier) VerifyAccountCode(_ context.Context, account models.Account, _ string) error {
	v.during(account)
	return nil
}

// TestRemoveDeviceRefusesAStaleEnrolledStepUp: on a TOTP-enrolled account the
// device removal holds the password hash it verified, so a password change by
// the same session landing during the step-up makes the removal refuse
// (ErrInvalidCurrentPassword) and keeps the device.
func TestRemoveDeviceRefusesAStaleEnrolledStepUp(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, sessionToken, _, _ := enrollTOTP(t, auth, totp, now)
	store := auth.store
	ctx := context.Background()

	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1024})
	if _, err := syncService.AttachDevice(ctx, accountID, "device-abcd1234", "phone"); err != nil {
		t.Fatalf("attach device: %v", err)
	}
	tokenHash := security.HashToken(sessionToken)
	syncService.AttachTOTPCodeVerifier(midStepUpVerifier{during: func(account models.Account) {
		if err := store.ChangeAccountPassword(
			ctx, account.ID, account.PasswordHash, account.RecoveryCodeHash, "moved-hash", "moved-recovery", tokenHash,
		); err != nil {
			t.Fatalf("change password mid step-up: %v", err)
		}
	}})

	stepUp := StepUp{SessionTokenHash: tokenHash, CurrentPassword: stepUpTestPassword, TOTPCode: "123456"}
	if err := syncService.RemoveDevice(ctx, accountID, stepUp, "device-abcd1234"); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, accountID); err != nil || count != 1 {
		t.Fatalf("a refused removal must keep the device, got %d / %v", count, err)
	}
}

func TestStepUpWriteErrorTreatsAFlippedTOTPStateAsStale(t *testing.T) {
	if got := stepUpWriteError(db.ErrTOTPStateChanged); got != ErrInvalidCurrentPassword {
		t.Fatalf("stepUpWriteError(ErrTOTPStateChanged) = %v, want ErrInvalidCurrentPassword", got)
	}
}
