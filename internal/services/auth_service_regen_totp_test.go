package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

const regenTOTPPassword = "correct horse battery staple"

type regenTOTPFixture struct {
	auth         *AuthService
	totp         *TOTPService
	accountID    string
	recovery     string
	secret       []byte
	enrollStep   int64
	recoveryHash string
}

func newRegenTOTPFixture(t *testing.T) regenTOTPFixture {
	t.Helper()

	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totpService := NewTOTPService(store, authService, key, "ovumcy-sync-community-test")
	authService.AttachTOTPChallengeIssuer(totpService)

	ctx := context.Background()
	registered, err := authService.Register(ctx, "owner@example.com", regenTOTPPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	start, err := totpService.StartEnrollment(ctx, registered.AccountID, regenTOTPPassword)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	enrollStep := time.Now().UTC().Unix() / security.TOTPStepSeconds
	if err := totpService.CompleteEnrollment(
		ctx,
		registered.AccountID,
		security.HashToken(registered.SessionToken),
		security.GenerateTOTPCode(secret, enrollStep),
	); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	account, err := store.FindAccountByID(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	return regenTOTPFixture{
		auth:         authService,
		totp:         totpService,
		accountID:    registered.AccountID,
		recovery:     registered.RecoveryCode,
		secret:       secret,
		enrollStep:   enrollStep,
		recoveryHash: account.RecoveryCodeHash,
	}
}

// Without a code the password alone must not rotate the recovery code: a
// reset with a freshly rotated code clears TOTP, so this is the path that
// would strip the second factor with only the first.
func TestRegenerateRecoveryCodeOnTOTPAccountRequiresCode(t *testing.T) {
	fixture := newRegenTOTPFixture(t)
	ctx := context.Background()

	for _, code := range []string{"", "000000"} {
		if _, err := fixture.auth.RegenerateRecoveryCode(ctx, fixture.accountID, regenTOTPPassword, code); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("code %q: expected ErrTOTPInvalidCode, got %v", code, err)
		}
	}

	account, err := fixture.auth.store.FindAccountByID(ctx, fixture.accountID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.RecoveryCodeHash != fixture.recoveryHash {
		t.Fatal("a rejected regeneration must leave the recovery code untouched")
	}
	if !account.TOTPEnabled {
		t.Fatal("TOTP must stay enabled")
	}
	if _, err := fixture.auth.ForgotPassword(ctx, "owner@example.com", fixture.recovery); err != nil {
		t.Fatalf("the original recovery code must still work: %v", err)
	}
}

func TestRegenerateRecoveryCodeOnTOTPAccountAcceptsCurrentCodeOnce(t *testing.T) {
	fixture := newRegenTOTPFixture(t)
	ctx := context.Background()
	code := security.GenerateTOTPCode(fixture.secret, fixture.enrollStep+1)

	newRecovery, err := fixture.auth.RegenerateRecoveryCode(ctx, fixture.accountID, regenTOTPPassword, code)
	if err != nil {
		t.Fatalf("regenerate with a current code: %v", err)
	}
	if newRecovery == "" || newRecovery == fixture.recovery {
		t.Fatalf("expected a new recovery code, got %q", newRecovery)
	}

	// The step is claimed: the same code cannot be replayed on another path.
	if err := fixture.totp.Disable(ctx, fixture.accountID, regenTOTPPassword, code); !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected ErrTOTPReplayed on reuse, got %v", err)
	}
}

// Wrong password with a valid code: refused before the code is looked at, so
// no attempt is spent and the code stays usable.
func TestRegenerateRecoveryCodeOnTOTPAccountChecksPasswordFirst(t *testing.T) {
	fixture := newRegenTOTPFixture(t)
	ctx := context.Background()
	code := security.GenerateTOTPCode(fixture.secret, fixture.enrollStep+1)

	if _, err := fixture.auth.RegenerateRecoveryCode(ctx, fixture.accountID, "wrong password", code); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
	if _, err := fixture.auth.RegenerateRecoveryCode(ctx, fixture.accountID, regenTOTPPassword, code); err != nil {
		t.Fatalf("the code must still be usable after a wrong-password attempt: %v", err)
	}
}

// An enrolled account on a service with no TOTP verifier wired fails closed
// rather than rotating on the password alone.
func TestRegenerateRecoveryCodeOnTOTPAccountFailsClosedWithoutVerifier(t *testing.T) {
	fixture := newRegenTOTPFixture(t)
	ctx := context.Background()

	bare := NewAuthService(fixture.auth.store, 24*time.Hour)
	if _, err := bare.RegenerateRecoveryCode(ctx, fixture.accountID, regenTOTPPassword, "123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("expected ErrTOTPNotConfigured, got %v", err)
	}

	unkeyed := NewTOTPService(fixture.auth.store, bare, nil, "ovumcy-sync-community-test")
	bare.AttachTOTPChallengeIssuer(unkeyed)
	if _, err := bare.RegenerateRecoveryCode(ctx, fixture.accountID, regenTOTPPassword, "123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("expected ErrTOTPNotConfigured from an unkeyed verifier, got %v", err)
	}
}
