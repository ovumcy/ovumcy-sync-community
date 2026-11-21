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
	// KeepStoredPackage is the caller's UnchangedRecoveryKeyPackage verdict.
	// Rekey does not re-read it: the transport charges the step-up bucket from
	// that same verdict, so a second read could check a password unmetered.
	// The store re-checks it inside the write (ErrRecoveryKeyChanged).
	KeepStoredPackage bool
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
	guard := db.RekeyGuard{Mode: db.RekeyKeepPackage, SessionTokenHash: stepUp.SessionTokenHash}
	if !input.KeepStoredPackage {
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
		// After both bodies are validated and a stale generation is ruled out,
		// so a rejected request does not spend the code's step (the step stays
		// claimed even when the write then refuses).
		if account.TOTPEnabled {
			if err := s.precheckRekeyGeneration(ctx, accountID, blob.Generation, ceiling, *input.ExpectedGeneration); err != nil {
				return models.RecoveryKeyPackage{}, models.EncryptedBlob{}, err
			}
		}
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

// precheckRekeyGeneration answers ErrStaleGeneration ahead of the TOTP code
// when the stored generation already refuses writeEncryptedBlob's predicate.
// It authorizes nothing; a write it lets through is still decided by the
// transaction.
func (s *SyncService) precheckRekeyGeneration(ctx context.Context, accountID string, generation, ceiling, expected int64) error {
	stored, found, err := s.store.EncryptedBlobGeneration(ctx, accountID)
	if err != nil {
		return err
	}
	switch {
	case expected == 0 && found,
		expected > 0 && (!found || stored != expected),
		found && stored >= generation && stored <= ceiling:
		return ErrStaleGeneration
	}
	return nil
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
