package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// ErrSessionRevoked is returned by a step-up write when the caller's session
// no longer exists, while the account itself does.
var ErrSessionRevoked = errors.New("session_revoked")

// requireStepUpState holds a step-up write to the state its re-authentication
// saw: the caller's session still exists and the password hash is still the one
// the password was verified against. A password change or reset, or a session
// revocation, landing during the bcrypt compare makes the write refuse instead
// of running on a stale verification. ErrNotFound when the account is gone,
// ErrSessionRevoked when only the caller's session is, ErrConflict when the
// hash moved on. The store's single connection makes this read and the write
// after it one atomic unit inside the transaction.
func requireStepUpState(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
	verifiedHash string,
	sessionTokenHash string,
) error {
	var storedHash string
	var sessionLive bool
	err := tx.QueryRowContext(
		ctx,
		`SELECT password_hash,
		        EXISTS (SELECT 1 FROM sessions WHERE account_id = accounts.id AND token_hash = ?)
		 FROM accounts WHERE id = ?`,
		sessionTokenHash,
		accountID,
	).Scan(&storedHash, &sessionLive)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("step-up state lookup: %w", err)
	case !sessionLive:
		return ErrSessionRevoked
	case storedHash != verifiedHash:
		return ErrConflict
	}
	return nil
}

// requireLiveSession holds a session-authenticated write to its caller: the
// write runs only while the caller's session still exists, so a request whose
// body arrived after a revocation (a password change or reset, a TOTP change,
// a device removal) changes nothing. ErrNotFound when the account is gone,
// ErrSessionRevoked when only the session is. As in requireStepUpState, the
// single connection makes this read and the write after it one atomic unit.
func requireLiveSession(ctx context.Context, tx *sql.Tx, accountID string, sessionTokenHash string) error {
	var sessionLive bool
	err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (SELECT 1 FROM sessions WHERE account_id = accounts.id AND token_hash = ?)
		 FROM accounts WHERE id = ?`,
		sessionTokenHash,
		accountID,
	).Scan(&sessionLive)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return fmt.Errorf("session lookup: %w", err)
	case !sessionLive:
		return ErrSessionRevoked
	}
	return nil
}

// DeleteAccountForSession is DeleteAccount for a session-authenticated caller:
// the erase runs only while requireStepUpState holds, in the same transaction.
func (s *Store) DeleteAccountForSession(
	ctx context.Context,
	accountID string,
	verifiedHash string,
	sessionTokenHash string,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete account: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := requireStepUpState(ctx, tx, accountID, verifiedHash, sessionTokenHash); err != nil {
		return err
	}
	if err := deleteAccountRows(ctx, tx, accountID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete account: %w", err) // codecov:ignore -- COMMIT on a transaction whose statements all succeeded needs a fake driver, the same deviation documented for DeleteAccount's COMMIT branch in fault_injection_test.go.
	}
	return nil
}

// UpsertRecoveryKeyPackageForSession is UpsertRecoveryKeyPackage for a
// session-authenticated caller: the overwrite runs only while
// requireStepUpState holds, in the same transaction.
func (s *Store) UpsertRecoveryKeyPackageForSession(
	ctx context.Context,
	recoveryKeyPackage models.RecoveryKeyPackage,
	verifiedHash string,
	sessionTokenHash string,
) (models.RecoveryKeyPackage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("begin upsert recovery key package: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := requireStepUpState(ctx, tx, recoveryKeyPackage.AccountID, verifiedHash, sessionTokenHash); err != nil {
		return models.RecoveryKeyPackage{}, err
	}
	stored, err := upsertRecoveryKeyPackage(ctx, tx, recoveryKeyPackage)
	if err != nil {
		return models.RecoveryKeyPackage{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("commit upsert recovery key package: %w", err) // codecov:ignore -- COMMIT on a transaction whose statements all succeeded needs a fake driver, the same deviation documented for DeleteAccount's COMMIT branch in fault_injection_test.go.
	}
	return stored, nil
}
