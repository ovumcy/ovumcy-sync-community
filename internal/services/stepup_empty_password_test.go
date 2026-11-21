package services

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A caller that charged no step-up slot (it authenticated the account before
// TOTP was enrolled) is refused before any password compare, even with the
// right password and code, and the device stays.
func TestRemoveDeviceUnmeteredOnAnEnrolledAccountComparesNoPassword(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	f.attachDevice(t, "device-totp1111")

	// An empty password would answer ErrCurrentPasswordMissing had the
	// compare been reached.
	for _, password := range []string{totpWindowTestPassword, ""} {
		stepUp := f.stepUp(f.code())
		stepUp.CurrentPassword = password
		stepUp.Unmetered = true
		if err := f.sync.RemoveDevice(ctx, f.accountID, stepUp, "device-totp1111"); !errors.Is(err, ErrInvalidCurrentPassword) {
			t.Fatalf("password %q: expected ErrInvalidCurrentPassword, got %v", password, err)
		}
	}
	if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(f.code()), "device-totp1111"); err != nil {
		t.Fatalf("the device and the code must survive the refusal: %v", err)
	}
}

// Every step-up refuses an empty password as missing, not wrong, so the API
// can give the slot back.
func TestStepUpsRefuseAnEmptyPasswordAsMissing(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	empty := f.stepUp(f.code())
	empty.CurrentPassword = ""

	checks := map[string]func() error{
		"delete account": func() error { return f.auth.DeleteAccount(ctx, f.accountID, empty) },
		"recovery key": func() error {
			_, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, empty, validRecoveryKeyInput(strings.Repeat("c", 16)))
			return err
		},
		"change password": func() error {
			_, err := f.auth.ChangePassword(ctx, f.accountID, f.sessionHash, "", "new staple battery horse correct", f.code())
			return err
		},
		"regenerate": func() error {
			_, err := f.auth.RegenerateRecoveryCode(ctx, f.accountID, empty, f.code())
			return err
		},
		"totp disable": func() error { return f.totp.Disable(ctx, f.accountID, empty) },
	}
	for name, check := range checks {
		if err := check(); !errors.Is(err, ErrCurrentPasswordMissing) {
			t.Fatalf("%s: expected ErrCurrentPasswordMissing, got %v", name, err)
		}
	}
}
