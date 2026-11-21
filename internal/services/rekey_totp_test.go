package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// On a TOTP-enrolled account a differing package needs a current code; a
// refusal writes neither part.
func TestRekeyOnTOTPAccountRequiresCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	input := RekeyInput{
		RecoveryKey:        validRecoveryKeyInput(strings.Repeat("c", 16)),
		Blob:               rekeyBlobInput("sealed-under-k1", base),
		ExpectedGeneration: expectGeneration(0),
	}

	for _, code := range []string{"", wrongTOTPCode(t, f.secret, f.later)} {
		if _, _, err := f.sync.Rekey(ctx, f.accountID, f.stepUp(code), input); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("code %q: expected ErrTOTPInvalidCode, got %v", code, err)
		}
	}
	if _, err := f.sync.GetRecoveryKeyPackage(ctx, f.accountID); !errors.Is(err, ErrRecoveryPackageNotFound) {
		t.Fatalf("a refused rekey stored a package: %v", err)
	}
	if _, err := f.sync.GetBlob(ctx, f.accountID); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("a refused rekey stored a blob: %v", err)
	}

	if _, _, err := f.sync.Rekey(ctx, f.accountID, f.stepUp(f.code()), input); err != nil {
		t.Fatalf("rekey with a current code: %v", err)
	}
}

// A rejected body or a generation the write would refuse is answered before
// the code is checked, so the code's step stays usable.
func TestRekeyOnTOTPAccountRefusesBeforeSpendingTheCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	if _, err := f.sync.PutBlob(ctx, f.accountID, f.stepUp("").SessionTokenHash, rekeyBlobInput("existing", base)); err != nil {
		t.Fatalf("seed blob: %v", err)
	}

	invalid := validRecoveryKeyInput(strings.Repeat("c", 16))
	invalid.MnemonicWordCount = 24
	refusals := map[string]struct {
		input RekeyInput
		want  error
	}{
		"invalid package": {RekeyInput{RecoveryKey: invalid, Blob: rekeyBlobInput("k1", base+1), ExpectedGeneration: expectGeneration(base)}, ErrInvalidRecoveryPackage},
		"stale expected":  {RekeyInput{RecoveryKey: validRecoveryKeyInput(strings.Repeat("c", 16)), Blob: rekeyBlobInput("k1", base+1), ExpectedGeneration: expectGeneration(base - 1)}, ErrStaleGeneration},
		"blob present":    {RekeyInput{RecoveryKey: validRecoveryKeyInput(strings.Repeat("c", 16)), Blob: rekeyBlobInput("k1", base+1), ExpectedGeneration: expectGeneration(0)}, ErrStaleGeneration},
		"no advance":      {RekeyInput{RecoveryKey: validRecoveryKeyInput(strings.Repeat("c", 16)), Blob: rekeyBlobInput("k1", base), ExpectedGeneration: expectGeneration(base)}, ErrStaleGeneration},
	}
	for name, refusal := range refusals {
		if _, _, err := f.sync.Rekey(ctx, f.accountID, f.stepUp(f.code()), refusal.input); !errors.Is(err, refusal.want) {
			t.Fatalf("%s: expected %v, got %v", name, refusal.want, err)
		}
	}

	if _, _, err := f.sync.Rekey(ctx, f.accountID, f.stepUp(f.code()), RekeyInput{
		RecoveryKey:        validRecoveryKeyInput(strings.Repeat("c", 16)),
		Blob:               rekeyBlobInput("k1", base+1),
		ExpectedGeneration: expectGeneration(base),
	}); err != nil {
		t.Fatalf("the code must still be usable after the refusals: %v", err)
	}
}

// A package sent as unchanged that is no longer the stored one stores no
// blob sealed under the old key.
func TestRekeyKeepPackageRefusesAReplacedPackage(t *testing.T) {
	syncService, registered := newRekeyFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()
	seedRekey(t, syncService, registered, base)
	if _, err := syncService.PutRecoveryKeyPackage(ctx, registered.AccountID, ownerStepUp(registered), rekeyedPackageInput()); err != nil {
		t.Fatalf("replace package: %v", err)
	}

	_, _, err := syncService.Rekey(ctx, registered.AccountID, StepUp{SessionTokenHash: ownerStepUp(registered).SessionTokenHash}, RekeyInput{
		RecoveryKey:        validRecoveryKeyPackageInput(),
		Blob:               rekeyBlobInput("still-k1", base+1),
		ExpectedGeneration: expectGeneration(base),
		KeepStoredPackage:  true,
	})
	if !errors.Is(err, ErrRecoveryKeyChanged) {
		t.Fatalf("expected ErrRecoveryKeyChanged, got %v", err)
	}
	assertRekeyState(t, syncService, registered.AccountID, strings.Repeat("f", 16), "sealed-under-k1")
}
