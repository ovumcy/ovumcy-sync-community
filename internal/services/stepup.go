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
}

// TOTPCodeVerifier checks a current TOTP code for an enrolled account,
// meters it in the account's failure window and claims its step
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

// verifyStepUp re-checks the session owner's password and returns the account
// as read, whose PasswordHash the write must then hold to in its own
// transaction. A wrong password returns the same ErrInvalidCurrentPassword as
// every other step-up, after a full bcrypt compare. Managed accounts have no
// password (sessions come only from the managed bridge, whose own
// re-authentication stands in), so they pass.
func verifyStepUp(
	ctx context.Context,
	store *db.Store,
	accountID string,
	currentPassword string,
) (models.Account, error) {
	account, err := store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return models.Account{}, ErrUnauthorized
		}
		return models.Account{}, err
	}

	if account.Mode == "managed" {
		return account, nil
	}

	if err := security.ComparePasswordHash(account.PasswordHash, currentPassword); err != nil {
		return models.Account{}, ErrInvalidCurrentPassword
	}
	return account, nil
}

// stepUpWriteError maps a step-up store write's refusal: a hash that moved
// during the compare is a stale verification, a vanished session or account
// is no longer an authenticated caller.
func stepUpWriteError(err error) error {
	switch {
	case errors.Is(err, db.ErrConflict):
		return ErrInvalidCurrentPassword
	case errors.Is(err, db.ErrSessionRevoked), errors.Is(err, db.ErrNotFound):
		return ErrUnauthorized
	}
	return err
}
