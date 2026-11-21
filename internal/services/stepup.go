package services

import (
	"context"
	"errors"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// StepUp is the re-authentication a write a stolen session must not be able
// to make alone carries (account deletion, the recovery-key overwrite): the
// caller's session, by token hash, the password it re-entered, and on a
// TOTP-enrolled account a current code (verifyStepUpCode).
type StepUp struct {
	SessionTokenHash string
	CurrentPassword  string
	TOTPCode         string
	// Unmetered: the caller charged no step-up slot, having authenticated an
	// account without TOTP. A removal that finds TOTP enrolled since then
	// refuses as a stale verification instead of comparing a password
	// unmetered (RemoveDevice).
	Unmetered bool
}

// TOTPCodeVerifier checks a current TOTP code for an enrolled account,
// draws it from the in-session step-up budget and claims its step
// (TOTPService.VerifyAccountCode).
type TOTPCodeVerifier interface {
	VerifyAccountCode(ctx context.Context, account models.Account, code string) error
}

// verifyStepUpCode asks a TOTP-enrolled account for a current code; an
// account without TOTP passes. No configured verifier fails closed rather than
// letting the first factor alone through.
func verifyStepUpCode(ctx context.Context, verifier TOTPCodeVerifier, account models.Account, code string) error {
	if !account.TOTPEnabled {
		return nil
	}
	if verifier == nil {
		return ErrTOTPNotConfigured
	}
	return verifier.VerifyAccountCode(ctx, account, code)
}

// ErrManagedStepUp: a managed account has no password, so no step-up can
// pass for it. A write a managed session may make handles that account before
// asking for a step-up.
var ErrManagedStepUp = errors.New("managed_account_step_up")

// verifyStepUp re-checks the session owner's password and returns the account
// as read, whose PasswordHash the write must then hold to in its own
// transaction. A wrong password returns the same ErrInvalidCurrentPassword as
// every other step-up, after a full bcrypt compare; a managed account returns
// ErrManagedStepUp.
func verifyStepUp(
	ctx context.Context,
	store *db.Store,
	accountID string,
	currentPassword string,
) (models.Account, error) {
	account, err := findStepUpAccount(ctx, store, accountID)
	if err != nil {
		return models.Account{}, err
	}
	if err := checkStepUpPassword(account, currentPassword); err != nil {
		return models.Account{}, err
	}
	return account, nil
}

// findStepUpAccount reads the session owner's account; an account gone since
// the session was authenticated is no longer an authenticated caller.
func findStepUpAccount(ctx context.Context, store *db.Store, accountID string) (models.Account, error) {
	account, err := store.FindAccountByID(ctx, accountID)
	if errors.Is(err, db.ErrNotFound) {
		return models.Account{}, ErrUnauthorized
	}
	return account, err
}

func checkStepUpPassword(account models.Account, currentPassword string) error {
	if account.Mode == "managed" {
		return ErrManagedStepUp
	}
	return compareCurrentPassword(account.PasswordHash, currentPassword)
}

// ErrCurrentPasswordMissing: a step-up sent no current password. The API
// answers it as 401 invalid_current_password, but nothing was guessed, so the
// step-up slot is given back.
var ErrCurrentPasswordMissing = errors.New("current_password_missing")

// compareCurrentPassword is every step-up's password check: an empty password
// is refused before bcrypt (ErrCurrentPasswordMissing), a wrong one after a
// full compare (ErrInvalidCurrentPassword).
func compareCurrentPassword(passwordHash string, currentPassword string) error {
	if currentPassword == "" {
		return ErrCurrentPasswordMissing
	}
	if err := security.ComparePasswordHash(passwordHash, currentPassword); err != nil {
		return ErrInvalidCurrentPassword
	}
	return nil
}

// stepUpWriteError maps a step-up store write's refusal: a hash that moved, or
// a TOTP enrollment that flipped, during the compare is a stale verification
// (as in ChangePassword); a vanished session or account is no longer an
// authenticated caller.
func stepUpWriteError(err error) error {
	switch {
	case errors.Is(err, db.ErrConflict), errors.Is(err, db.ErrTOTPStateChanged):
		return ErrInvalidCurrentPassword
	case errors.Is(err, db.ErrSessionRevoked), errors.Is(err, db.ErrNotFound):
		return ErrUnauthorized
	}
	return err
}
