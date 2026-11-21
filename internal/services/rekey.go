package services

import (
	"context"
	"errors"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// ErrRecoveryKeyChanged: a re-key whose package equals the stored one found
// another package stored by the time it wrote; nothing was written.
var ErrRecoveryKeyChanged = errors.New("recovery_key_changed")

// RekeyInput is PUT /sync/rekey's body: a package, the blob sealed under it,
// and the generation the client last saw stored (0 = none).
type RekeyInput struct {
	RecoveryKey        PutRecoveryKeyPackageInput
	Blob               PutBlobInput
	ExpectedGeneration *int64
}

// Rekey stores a recovery-key package and the blob sealed under it in one
// transaction, so a failed blob write can never leave a package the stored
// blob is not sealed under. The package follows PutRecoveryKeyPackage's rules
// (no step-up when unchanged; password before validation, code after it;
// managed accounts store a first package only); the blob follows PutBlob's,
// with ExpectedGeneration required.
func (s *SyncService) Rekey(
	ctx context.Context,
	accountID string,
	stepUp StepUp,
	input RekeyInput,
) (models.RecoveryKeyPackage, models.EncryptedBlob, error) {
	if input.ExpectedGeneration == nil || *input.ExpectedGeneration < 0 {
		return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, ErrInvalidBlob
	}
	recoveryKeyPackage := normalizeRecoveryKeyPackage(accountID, input.RecoveryKey)
	_, unchanged, err := s.matchStoredRecoveryKeyPackage(ctx, recoveryKeyPackage)
	if err != nil {
		return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
	}

	guard := db.RekeyGuard{Mode: db.RekeyKeepPackage, SessionTokenHash: stepUp.SessionTokenHash}
	if !unchanged {
		account, err := findStepUpAccount(ctx, s.store, accountID)
		if err != nil {
			return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
		}
		guard.Mode = db.RekeyFirstManaged
		if account.Mode != "managed" {
			if err := checkStepUpPassword(account, stepUp.CurrentPassword); err != nil {
				return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
			}
			guard.Mode = db.RekeyStepUp
			guard.VerifiedHash = account.PasswordHash
			guard.VerifiedTOTPEnabled = account.TOTPEnabled
		}
		if err := validateRecoveryKeyPackage(recoveryKeyPackage); err != nil {
			return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
		}
		blob, ceiling, err := s.validatedBlob(accountID, input.Blob)
		if err != nil {
			return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
		}
		// After both bodies are validated, so a rejected body does not spend
		// the code's step.
		if err := verifyStepUpCode(ctx, s.totpCodes, account, stepUp.TOTPCode); err != nil {
			return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
		}
		return s.writeRekey(ctx, recoveryKeyPackage, blob, guard, ceiling, *input.ExpectedGeneration)
	}

	blob, ceiling, err := s.validatedBlob(accountID, input.Blob)
	if err != nil {
		return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
	}
	return s.writeRekey(ctx, recoveryKeyPackage, blob, guard, ceiling, *input.ExpectedGeneration)
}

func (s *SyncService) writeRekey(
	ctx context.Context,
	recoveryKeyPackage models.RecoveryKeyPackage,
	blob models.EncryptedBlob,
	guard db.RekeyGuard,
	ceiling int64,
	expectedGeneration int64,
) (models.RecoveryKeyPackage, models.EncryptedBlob, error) {
	recoveryKeyPackage.UpdatedAt = s.now().UTC()
	stored, err := s.store.ReplaceRecoveryKeyAndBlobForSession(ctx, recoveryKeyPackage, blob, guard, ceiling, expectedGeneration)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrStaleGeneration):
			err = ErrStaleGeneration
		case errors.Is(err, db.ErrRecoveryKeyChanged):
			err = ErrRecoveryKeyChanged
		case guard.Mode == db.RekeyFirstManaged && errors.Is(err, db.ErrConflict):
			err = ErrManagedRecoveryKeyOverwrite
		default:
			err = stepUpWriteError(err)
		}
		return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
	}
	return stored, blob, nil
}
