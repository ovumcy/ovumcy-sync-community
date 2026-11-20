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

// ErrPasswordChanged is returned by a step-up write whose ErrConflict is
// already taken by another refusal, when the password hash moved on since it
// was verified.
var ErrPasswordChanged = errors.New("password_changed")

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

// DeleteAccountForSession erases every row this server holds for accountID
// (deleteAccountRows) for a session-authenticated caller: the erase runs only
// while requireStepUpState holds, in the same transaction.
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
	if err := deleteAccountRows(ctx, tx, accountID, deleteAnyAccountSQL); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete account: %w", err) // codecov:ignore -- COMMIT on a transaction whose statements all succeeded needs a fake driver, the same deviation documented for DeleteManagedAccount's COMMIT branch in fault_injection_test.go.
	}
	s.checkpointAfterErase(ctx)
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
		return models.RecoveryKeyPackage{}, fmt.Errorf("commit upsert recovery key package: %w", err) // codecov:ignore -- COMMIT on a transaction whose statements all succeeded needs a fake driver, the same deviation documented for DeleteManagedAccount's COMMIT branch in fault_injection_test.go.
	}
	return stored, nil
}

// InsertRecoveryKeyPackageForSession stores a first wrapped recovery key for a
// session-authenticated caller that has no password to re-check (a managed
// account): it writes only while the caller's session exists
// (requireLiveSession) and never replaces a stored package — one already
// there, a concurrent first put's included, answers ErrConflict unless its
// content equals this one, which returns the stored row unwritten.
func (s *Store) InsertRecoveryKeyPackageForSession(
	ctx context.Context,
	recoveryKeyPackage models.RecoveryKeyPackage,
	sessionTokenHash string,
) (models.RecoveryKeyPackage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("begin insert recovery key package: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := requireLiveSession(ctx, tx, recoveryKeyPackage.AccountID, sessionTokenHash); err != nil {
		return models.RecoveryKeyPackage{}, err
	}
	result, err := tx.ExecContext(
		ctx,
		insertRecoveryKeyPackageSQL+`ON CONFLICT(account_id) DO NOTHING`,
		recoveryKeyPackageArgs(recoveryKeyPackage)...,
	)
	if err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("insert recovery key package: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("insert recovery key package rows: %w", err) // codecov:ignore -- the SQLite driver reports RowsAffected from the completed exec and does not fail here.
	}
	if inserted == 0 {
		stored, err := scanRecoveryKeyPackage(tx.QueryRowContext(ctx, selectRecoveryKeyPackageSQL, recoveryKeyPackage.AccountID))
		if err != nil {
			return models.RecoveryKeyPackage{}, err // codecov:ignore -- the conflicting row was just seen inside this transaction on the store's single connection; only a driver fault fails this read.
		}
		content := stored
		content.UpdatedAt = recoveryKeyPackage.UpdatedAt
		if content != recoveryKeyPackage {
			return models.RecoveryKeyPackage{}, ErrConflict
		}
		return stored, nil
	}

	if err := tx.Commit(); err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("commit insert recovery key package: %w", err) // codecov:ignore -- COMMIT on a transaction whose statements all succeeded needs a fake driver, the same deviation documented for DeleteManagedAccount's COMMIT branch in fault_injection_test.go.
	}
	return recoveryKeyPackage, nil
}
