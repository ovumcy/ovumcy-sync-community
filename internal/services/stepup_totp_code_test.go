package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

type stepUpCodeFixture struct {
	auth        *AuthService
	totp        *TOTPService
	sync        *SyncService
	accountID   string
	sessionHash string
	secret      []byte
	later       time.Time
}

// newStepUpCodeFixture enrolls an account and moves the clock one step past
// the enrollment code, so the current step's code is unspent.
func newStepUpCodeFixture(t *testing.T) stepUpCodeFixture {
	t.Helper()
	auth, totp, now := fixedTOTPClock(t)
	accountID, token, secret, _ := enrollTOTP(t, auth, totp, now)
	sync := NewSyncService(auth.store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1 << 20})
	sync.AttachTOTPCodeVerifier(totp)
	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	return stepUpCodeFixture{
		auth:        auth,
		totp:        totp,
		sync:        sync,
		accountID:   accountID,
		sessionHash: security.HashToken(token),
		secret:      secret,
		later:       later,
	}
}

func (f stepUpCodeFixture) code() string {
	return security.GenerateTOTPCode(f.secret, f.later.Unix()/security.TOTPStepSeconds)
}

func (f stepUpCodeFixture) stepUp(code string) StepUp {
	return StepUp{SessionTokenHash: f.sessionHash, CurrentPassword: totpWindowTestPassword, TOTPCode: code}
}

func (f stepUpCodeFixture) attachDevice(t *testing.T, deviceID string) {
	t.Helper()
	if _, err := f.sync.AttachDevice(context.Background(), f.accountID, deviceID, "phone"); err != nil {
		t.Fatalf("attach device: %v", err)
	}
}

func validRecoveryKeyInput(fingerprint string) PutRecoveryKeyPackageInput {
	return PutRecoveryKeyPackageInput{
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: fingerprint,
	}
}

func TestDeleteAccountOnTOTPAccountRequiresCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()

	for _, code := range []string{"", wrongTOTPCode(t, f.secret, f.later)} {
		if err := f.auth.DeleteAccount(ctx, f.accountID, f.stepUp(code)); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("code %q: expected ErrTOTPInvalidCode, got %v", code, err)
		}
	}
	if _, err := f.auth.store.FindAccountByID(ctx, f.accountID); err != nil {
		t.Fatalf("a refused delete must keep the account: %v", err)
	}

	if err := f.auth.DeleteAccount(ctx, f.accountID, f.stepUp(f.code())); err != nil {
		t.Fatalf("delete with a current code: %v", err)
	}
	if _, err := f.auth.store.FindAccountByID(ctx, f.accountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected the account erased, got %v", err)
	}
}

// A wrong password is refused before the code is checked, so the code's step
// stays usable.
func TestDeleteAccountOnTOTPAccountChecksPasswordBeforeCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	wrong := f.stepUp(f.code())
	wrong.CurrentPassword = "not the password at all"

	if err := f.auth.DeleteAccount(ctx, f.accountID, wrong); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
	if err := f.auth.DeleteAccount(ctx, f.accountID, f.stepUp(f.code())); err != nil {
		t.Fatalf("the code must still be usable after a wrong password: %v", err)
	}
}

func TestPutRecoveryKeyOnTOTPAccountRequiresCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()

	for _, code := range []string{"", wrongTOTPCode(t, f.secret, f.later)} {
		if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(code), validRecoveryKeyInput(strings.Repeat("c", 16))); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("code %q: expected ErrTOTPInvalidCode, got %v", code, err)
		}
	}
	if _, err := f.sync.GetRecoveryKeyPackage(ctx, f.accountID); !errors.Is(err, ErrRecoveryPackageNotFound) {
		t.Fatalf("a refused overwrite must write nothing, got %v", err)
	}

	stored, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(f.code()), validRecoveryKeyInput(strings.Repeat("c", 16)))
	if err != nil {
		t.Fatalf("put with a current code: %v", err)
	}
	if stored.PhraseFingerprintHex != strings.Repeat("c", 16) {
		t.Fatalf("unexpected stored package %#v", stored)
	}
}

// A rejected package is refused before the code is checked, so the code's
// step stays usable.
func TestPutRecoveryKeyOnTOTPAccountValidatesPackageBeforeCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	invalid := validRecoveryKeyInput(strings.Repeat("c", 16))
	invalid.MnemonicWordCount = 24

	if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(f.code()), invalid); !errors.Is(err, ErrInvalidRecoveryPackage) {
		t.Fatalf("expected ErrInvalidRecoveryPackage, got %v", err)
	}
	if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(f.code()), validRecoveryKeyInput(strings.Repeat("c", 16))); err != nil {
		t.Fatalf("the code must still be usable after a rejected package: %v", err)
	}
}

func TestRemoveDeviceOnTOTPAccountRequiresCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	f.attachDevice(t, "device-totp1111")

	for _, code := range []string{"", wrongTOTPCode(t, f.secret, f.later)} {
		if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(code), "device-totp1111"); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("code %q: expected ErrTOTPInvalidCode, got %v", code, err)
		}
	}
	devices, err := f.sync.ListDevices(ctx, f.accountID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("a refused removal must keep the device, got %d devices, err %v", len(devices), err)
	}

	if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(f.code()), "device-totp1111"); err != nil {
		t.Fatalf("remove with a current code: %v", err)
	}
	devices, err = f.sync.ListDevices(ctx, f.accountID)
	if err != nil || len(devices) != 0 {
		t.Fatalf("expected the device removed, got %d devices, err %v", len(devices), err)
	}
}

// An enrolled account's removal needs the password too, checked first: a
// wrong one keeps the device and leaves the code's step usable.
func TestRemoveDeviceOnTOTPAccountRequiresPasswordBeforeCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	f.attachDevice(t, "device-totp1111")

	for _, password := range []string{"", "not the password at all"} {
		stepUp := f.stepUp(f.code())
		stepUp.CurrentPassword = password
		if err := f.sync.RemoveDevice(ctx, f.accountID, stepUp, "device-totp1111"); !errors.Is(err, ErrInvalidCurrentPassword) {
			t.Fatalf("password %q: expected ErrInvalidCurrentPassword, got %v", password, err)
		}
	}
	if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(f.code()), "device-totp1111"); err != nil {
		t.Fatalf("the code must still be usable after a wrong password: %v", err)
	}
}

// An empty device id is refused before the code is checked.
func TestRemoveDeviceOnTOTPAccountValidatesIDBeforeCode(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	f.attachDevice(t, "device-totp1111")

	if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(f.code()), "  "); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("expected ErrInvalidDevice, got %v", err)
	}
	if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(f.code()), "device-totp1111"); err != nil {
		t.Fatalf("the code must still be usable after an invalid id: %v", err)
	}
}

func TestStepUpCodeRoutesFailClosedWithoutVerifier(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	unwiredAuth := NewAuthService(f.auth.store, 24*time.Hour)
	unwiredSync := NewSyncService(f.auth.store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1 << 20})
	f.attachDevice(t, "device-totp1111")

	if err := unwiredAuth.DeleteAccount(ctx, f.accountID, f.stepUp(f.code())); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("delete: expected ErrTOTPNotConfigured, got %v", err)
	}
	if _, err := unwiredSync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(f.code()), validRecoveryKeyInput(strings.Repeat("c", 16))); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("recovery key: expected ErrTOTPNotConfigured, got %v", err)
	}
	if err := unwiredSync.RemoveDevice(ctx, f.accountID, f.stepUp(f.code()), "device-totp1111"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("remove device: expected ErrTOTPNotConfigured, got %v", err)
	}
}

// Wrong codes on device removal spend the same per-account window as every
// other code check, so removal is no extra code oracle; missing codes spend
// none of it.
func TestRemoveDeviceSharesTheAccountTOTPWindow(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()

	for range maxTOTPAccountFailedAttempts {
		if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(""), "device-totp1111"); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("missing code: expected ErrTOTPInvalidCode, got %v", err)
		}
	}
	wrong := wrongTOTPCode(t, f.secret, f.later)
	for range maxTOTPAccountFailedAttempts {
		if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(wrong), "device-totp1111"); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("wrong code: expected ErrTOTPInvalidCode, got %v", err)
		}
	}

	if err := f.auth.DeleteAccount(ctx, f.accountID, f.stepUp(f.code())); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected account deletion to share the lock, got %v", err)
	}
}

// A code spent on one step-up route cannot be replayed on another.
func TestStepUpCodeIsSingleUseAcrossRoutes(t *testing.T) {
	f := newStepUpCodeFixture(t)
	ctx := context.Background()
	f.attachDevice(t, "device-totp1111")
	code := f.code()

	if err := f.sync.RemoveDevice(ctx, f.accountID, f.stepUp(code), "device-totp1111"); err != nil {
		t.Fatalf("remove device: %v", err)
	}
	if _, err := f.sync.PutRecoveryKeyPackage(ctx, f.accountID, f.stepUp(code), validRecoveryKeyInput(strings.Repeat("c", 16))); !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("recovery key: expected ErrTOTPReplayed, got %v", err)
	}
	if err := f.auth.DeleteAccount(ctx, f.accountID, f.stepUp(code)); !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("delete: expected ErrTOTPReplayed, got %v", err)
	}
}

// A store failure on the account read surfaces as-is: neither a 401 nor a
// silent pass without the TOTP check.
func TestRemoveDeviceSurfacesAccountReadFailure(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	sync := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1 << 20})
	dropTable(t, dbPath, "accounts")

	err := sync.RemoveDevice(context.Background(), "account-x", StepUp{SessionTokenHash: "hash"}, "device-x1111111")
	if err == nil || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected the raw store error, got %v", err)
	}
}

// Removal reads the account for its TOTP state; an account already gone is no
// longer an authenticated caller.
func TestRemoveDeviceOnDeletedAccountIsUnauthorized(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	sync := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 1 << 20})
	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", totpWindowTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	sessionHash := security.HashToken(registered.SessionToken)
	if err := auth.DeleteAccount(ctx, registered.AccountID, StepUp{SessionTokenHash: sessionHash, CurrentPassword: totpWindowTestPassword}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if err := sync.RemoveDevice(ctx, registered.AccountID, StepUp{SessionTokenHash: sessionHash}, "device-gone1111"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}
