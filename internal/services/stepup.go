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
// caller's session, by token hash, and the password it re-entered.
type StepUp struct {
	SessionTokenHash string
	CurrentPassword  string
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
