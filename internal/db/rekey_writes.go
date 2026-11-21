package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// ErrRecoveryKeyChanged is returned by a re-key write judged against the
// stored package (RekeyKeepPackage) when that package is no longer the stored
// one: the blob was sealed under a key the account no longer holds.
var ErrRecoveryKeyChanged = errors.New("recovery_key_changed")

// RekeyMode is how a re-key write authorizes and writes its package.
type RekeyMode int

const (
	// RekeyKeepPackage writes only the blob, while the stored package still
	// equals the request's; no step-up.
	RekeyKeepPackage RekeyMode = iota
	// RekeyStepUp overwrites the package under requireStepUpState.
	RekeyStepUp
	// RekeyFirstManaged stores a managed account's first package, never
	// replacing a different stored one (ErrConflict).
	RekeyFirstManaged
)

// RekeyGuard carries what a re-key write re-checks in its transaction.
type RekeyGuard struct {
	Mode                RekeyMode
	SessionTokenHash    string
	VerifiedHash        string
	VerifiedTOTPEnabled bool
}

// ReplaceRecoveryKeyAndBlobForSession writes a recovery-key package and the
// blob sealed under it in one transaction: either both land or neither does.
// The blob write is writeEncryptedBlob with a required expectedGeneration
// (zero = no row stored yet), so the over-bound arm and its "never waives the
// expected match" rule are the same SQL as PUT /sync/blob's.
func (s *Store) ReplaceRecoveryKeyAndBlobForSession(
	ctx context.Context,
	recoveryKeyPackage models.RecoveryKeyPackage,
	blob models.EncryptedBlob,
	guard RekeyGuard,
	generationCeiling int64,
	expectedGeneration int64,
) (models.RecoveryKeyPackage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("begin rekey: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	accountID := recoveryKeyPackage.AccountID
	stored := recoveryKeyPackage
	switch guard.Mode {
	case RekeyStepUp:
		if err := requireStepUpState(ctx, tx, accountID, guard.VerifiedHash, guard.VerifiedTOTPEnabled, guard.SessionTokenHash); err != nil {
			return models.RecoveryKeyPackage{}, err
		}
		if stored, err = upsertRecoveryKeyPackage(ctx, tx, recoveryKeyPackage); err != nil {
			return models.RecoveryKeyPackage{}, err
		}
	case RekeyFirstManaged:
		if err := requireLiveSession(ctx, tx, accountID, guard.SessionTokenHash); err != nil {
			return models.RecoveryKeyPackage{}, err
		}
		result, err := tx.ExecContext(
			ctx,
			insertRecoveryKeyPackageSQL+`ON CONFLICT(account_id) DO NOTHING`,
			recoveryKeyPackageArgs(recoveryKeyPackage)...,
		)
		if err != nil {
			return models.RecoveryKeyPackage{}, fmt.Errorf("rekey insert recovery key package: %w", err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return models.RecoveryKeyPackage{}, fmt.Errorf("rekey insert recovery key package rows: %w", err) // codecov:ignore -- the SQLite driver reports RowsAffected from the completed exec and does not fail here.
		}
		if inserted == 0 {
			stored, err = requireStoredRecoveryKeyPackage(ctx, tx, recoveryKeyPackage)
			if errors.Is(err, ErrRecoveryKeyChanged) {
				return models.RecoveryKeyPackage{}, ErrConflict
			}
			if err != nil {
				return models.RecoveryKeyPackage{}, err // codecov:ignore -- the conflicting row was just seen inside this transaction on the store's single connection; only a driver fault fails this read.
			}
		}
	default:
		if err := requireLiveSession(ctx, tx, accountID, guard.SessionTokenHash); err != nil {
			return models.RecoveryKeyPackage{}, err
		}
		if stored, err = requireStoredRecoveryKeyPackage(ctx, tx, recoveryKeyPackage); err != nil {
			return models.RecoveryKeyPackage{}, err
		}
	}

	if err := writeEncryptedBlob(ctx, tx, generationCeiling, blob, &expectedGeneration); err != nil {
		return models.RecoveryKeyPackage{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("commit rekey: %w", err) // codecov:ignore -- COMMIT on a transaction whose statements all succeeded needs a fake driver, the same deviation documented for DeleteManagedAccount's COMMIT branch in fault_injection_test.go.
	}
	return stored, nil
}

// EncryptedBlobGeneration reads the stored blob's generation without its
// ciphertext; found is false when the account has no blob. Advisory only: the
// write's own statement decides.
func (s *Store) EncryptedBlobGeneration(ctx context.Context, accountID string) (generation int64, found bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT generation FROM encrypted_blobs WHERE account_id = ?`, accountID).Scan(&generation)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("blob generation lookup: %w", err)
	}
	return generation, true, nil
}

// requireStoredRecoveryKeyPackage returns the stored package when its content
// equals want's (updated_at aside), else ErrRecoveryKeyChanged — no row
// included.
func requireStoredRecoveryKeyPackage(
	ctx context.Context,
	tx *sql.Tx,
	want models.RecoveryKeyPackage,
) (models.RecoveryKeyPackage, error) {
	stored, err := scanRecoveryKeyPackage(tx.QueryRowContext(ctx, selectRecoveryKeyPackageSQL, want.AccountID))
	if errors.Is(err, ErrNotFound) {
		return models.RecoveryKeyPackage{}, ErrRecoveryKeyChanged
	}
	if err != nil {
		return models.RecoveryKeyPackage{}, err
	}
	content := stored
	content.UpdatedAt = want.UpdatedAt
	if content != want {
		return models.RecoveryKeyPackage{}, ErrRecoveryKeyChanged
	}
	return stored, nil
}
