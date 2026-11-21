package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

var ErrInvalidDevice = errors.New("invalid_device")

// MaxDeviceIDBytes and MaxDeviceLabelBytes cap what an attach stores. Removal
// does not check them, so a device attached before the caps can still go.
const (
	MaxDeviceIDBytes    = 128
	MaxDeviceLabelBytes = 64
)
var ErrTooManyDevices = errors.New("too_many_devices")
var ErrSessionDeviceBound = errors.New("session_device_bound")
var ErrDeviceNotFound = errors.New("device_not_found")
var ErrInvalidBlob = errors.New("invalid_blob")
var ErrBlobNotFound = errors.New("blob_not_found")
var ErrStaleGeneration = errors.New("stale_generation")
var ErrInvalidRecoveryPackage = errors.New("invalid_recovery_package")
var ErrRecoveryPackageNotFound = errors.New("recovery_package_not_found")

// ErrManagedRecoveryKeyOverwrite refuses a managed session's change to a
// stored recovery key: the account has no password to step up with, so the
// session alone would be enough. No session route replaces it; the bridge
// purge clears it with the rest of the account.
var ErrManagedRecoveryKeyOverwrite = errors.New("managed_recovery_key_overwrite")

var checksumPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var lowercaseHexPattern = regexp.MustCompile(`^[a-f0-9]+$`)

// blobGenerationSkew is how far ahead of this server's clock an accepted blob
// generation may sit. The client derives generation from a millisecond
// timestamp (ovumcy-app's nextRemoteGeneration, which is
// max(now_ms, last+1)), so a legitimate value never runs ahead of server time
// by more than the clock difference between the two machines plus a stray
// millisecond per same-millisecond write. The bound is also how long a
// generation parked at the ceiling by a since-revoked session keeps the
// owner's writes stale, so it stays short: 15 minutes covers real device
// clock drift and caps that lock-out.
const blobGenerationSkew = 15 * time.Minute

// maxAcceptableBlobGeneration bounds a write to a plausible timestamp, and it
// moves with the clock on purpose.
//
// A CONSTANT ceiling cannot work here, however high it is placed:
// UpsertEncryptedBlob's CAS accepts only a strictly greater generation
// (bar a stored row already above this bound), so
// whatever the highest accepted value is, one write at that value leaves the
// blob unreplaceable forever — every later write is either rejected by the
// ceiling or refused as stale. That is the owner's entire backup bricked by a
// single request from any device on the account, recoverable only by deleting
// the account. A moving bound has no terminal value: whatever was accepted a
// moment ago is beatable once the clock advances past it.
func maxAcceptableBlobGeneration(now time.Time) int64 {
	return now.UTC().Add(blobGenerationSkew).UnixMilli()
}

type SyncService struct {
	store        *db.Store
	maxDevices   int
	maxBlobBytes int
	now          func() time.Time
	totpCodes    TOTPCodeVerifier
}

type SyncOptions struct {
	MaxDevices   int
	MaxBlobBytes int
}

type PutBlobInput struct {
	SchemaVersion  int
	Generation     int64
	ChecksumSHA256 string
	Ciphertext     []byte
	// ExpectedGeneration, when set, is the generation the client last saw
	// stored; the write commits only while it is still the stored one.
	ExpectedGeneration *int64
}

type PutRecoveryKeyPackageInput struct {
	Algorithm            string
	KDF                  string
	MnemonicWordCount    int
	WrapNonceHex         string
	WrappedMasterKeyHex  string
	PhraseFingerprintHex string
}

func NewSyncService(store *db.Store, options SyncOptions) *SyncService {
	return &SyncService{
		store:        store,
		maxDevices:   options.MaxDevices,
		maxBlobBytes: options.MaxBlobBytes,
		now:          time.Now,
	}
}

// AttachTOTPCodeVerifier wires the TOTP code check that device removal and
// the recovery-key overwrite ask of an enrolled account. Left nil (no field
// encryption key), both fail closed on an enrolled account.
func (s *SyncService) AttachTOTPCodeVerifier(verifier TOTPCodeVerifier) {
	s.totpCodes = verifier
}

func (s *SyncService) Capabilities() models.CapabilityDocument {
	return models.CapabilityDocument{
		Mode:              "self_hosted",
		SyncEnabled:       true,
		PremiumActive:     false,
		RecoverySupported: true,
		PushSupported:     false,
		PortalSupported:   false,
		AdvancedInsights:  false,
		MaxDevices:        s.maxDevices,
		MaxBlobBytes:      int64(s.maxBlobBytes),
		AtomicRekey:       true,
	}
}

func (s *SyncService) CapabilitiesForAccount(account models.Account) models.CapabilityDocument {
	if account.Mode == "managed" {
		return models.CapabilityDocument{
			Mode:              "managed",
			SyncEnabled:       account.PremiumActive,
			PremiumActive:     account.PremiumActive,
			RecoverySupported: true,
			PushSupported:     false,
			PortalSupported:   false,
			AdvancedInsights:  false,
			MaxDevices:        s.maxDevices,
			MaxBlobBytes:      int64(s.maxBlobBytes),
			AtomicRekey:       true,
		}
	}

	return s.Capabilities()
}

func (s *SyncService) AttachDevice(
	ctx context.Context,
	accountID string,
	deviceID string,
	deviceLabel string,
) (models.Device, error) {
	device, err := s.newDeviceRow(accountID, deviceID, deviceLabel)
	if err != nil {
		return models.Device{}, err
	}
	// Atomic ceiling in the repository: the WHERE sub-select rejects an
	// attach that would exceed maxDevices in the same statement that
	// inserts, so we don't count-then-write here. Concurrent attaches that
	// all read the same count would otherwise each add a row and push the
	// account past its limit.
	return mapAttachError(s.store.UpsertDevice(ctx, device, s.maxDevices))
}

// AttachDeviceForSession attaches the device and binds the calling session to
// it, so removing the device later revokes that session. One device per
// session: a session already bound to a different device gets
// ErrSessionDeviceBound and nothing is attached; re-attaching its own device
// refreshes it.
func (s *SyncService) AttachDeviceForSession(
	ctx context.Context,
	accountID string,
	sessionTokenHash string,
	deviceID string,
	deviceLabel string,
) (models.Device, error) {
	device, err := s.newDeviceRow(accountID, deviceID, deviceLabel)
	if err != nil {
		return models.Device{}, err
	}
	return mapAttachError(s.store.AttachDeviceForSession(ctx, device, s.maxDevices, sessionTokenHash))
}

func (s *SyncService) newDeviceRow(accountID, deviceID, deviceLabel string) (models.Device, error) {
	deviceID = strings.TrimSpace(deviceID)
	deviceLabel = strings.TrimSpace(deviceLabel)
	if len(deviceID) < 8 || len(deviceID) > MaxDeviceIDBytes ||
		len(deviceLabel) < 2 || len(deviceLabel) > MaxDeviceLabelBytes {
		return models.Device{}, ErrInvalidDevice
	}
	now := s.now().UTC()
	return models.Device{
		DeviceID:    deviceID,
		AccountID:   accountID,
		DeviceLabel: deviceLabel,
		CreatedAt:   now,
		LastSeenAt:  now,
	}, nil
}

func mapAttachError(device models.Device, err error) (models.Device, error) {
	switch {
	case err == nil:
		return device, nil
	case errors.Is(err, db.ErrDeviceLimitReached):
		return models.Device{}, ErrTooManyDevices
	case errors.Is(err, db.ErrSessionDeviceBound):
		return models.Device{}, ErrSessionDeviceBound
	case errors.Is(err, db.ErrSessionRevoked):
		return models.Device{}, ErrUnauthorized
	default:
		return models.Device{}, err
	}
}

// ListDevices returns every device attached to the account, account-scoped.
func (s *SyncService) ListDevices(ctx context.Context, accountID string) ([]models.Device, error) {
	return s.store.ListDevicesForAccount(ctx, accountID)
}

// RemoveDevice detaches one device from the account so its slot is freed, and
// revokes every session bound to it (the caller's own included, when it is
// that device's session). The delete is account-scoped in the query (no IDOR).
// Returns ErrInvalidDevice for an empty id, ErrDeviceNotFound when the
// account has no such device, and ErrUnauthorized when the caller's session
// was revoked before the delete.
//
// A TOTP-enrolled account must re-enter its password and present a current
// code (password first, so a wrong one spends no code step), so a stolen
// session alone can neither evict the owner's devices nor spend the step-up
// TOTP budget. An account without TOTP needs only its session, as before.
// Any credential change by another session revokes this one, which the
// delete's session predicate catches; one by this same session (a TOTP
// enrollment, a password change) landing during the checks makes the delete
// refuse as a stale verification (ErrInvalidCurrentPassword). So does an
// enrollment found by a caller that charged no step-up slot (stepUp.Unmetered),
// before any password compare.
func (s *SyncService) RemoveDevice(ctx context.Context, accountID string, stepUp StepUp, deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return ErrInvalidDevice
	}

	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}
	if account.TOTPEnabled {
		if stepUp.Unmetered {
			return ErrInvalidCurrentPassword
		}
		if err := compareCurrentPassword(account.PasswordHash, stepUp.CurrentPassword); err != nil {
			return err
		}
		if err := verifyStepUpCode(ctx, s.totpCodes, account, stepUp.TOTPCode); err != nil {
			return err
		}
	}

	if err := s.store.DeleteDevice(
		ctx,
		accountID,
		stepUp.SessionTokenHash,
		deviceID,
		account.TOTPEnabled,
		account.PasswordHash,
	); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrDeviceNotFound
		}
		return stepUpWriteError(err)
	}

	return nil
}

// PutBlob stores the account's ciphertext while the caller's session still
// exists: a session revoked while the body was in flight writes nothing
// (ErrUnauthorized).
func (s *SyncService) PutBlob(
	ctx context.Context,
	accountID string,
	sessionTokenHash string,
	input PutBlobInput,
) (models.EncryptedBlob, error) {
	if input.ExpectedGeneration != nil && *input.ExpectedGeneration <= 0 {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}
	blob, ceiling, err := s.validatedBlob(accountID, input)
	if err != nil {
		return models.EncryptedBlob{}, err
	}

	// Atomic CAS in the repository: the WHERE excluded.generation >
	// encrypted_blobs.generation guard rejects concurrent writers that
	// passed the same baseline, so we don't read-then-write here; an
	// expected generation joins the same statement's predicate. A stored
	// generation above ceiling (pre-upgrade) is replaced by any valid write.
	stored, err := s.store.UpsertEncryptedBlobExpecting(ctx, sessionTokenHash, ceiling, blob, input.ExpectedGeneration)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrStaleGeneration):
			return models.EncryptedBlob{}, ErrStaleGeneration
		case errors.Is(err, db.ErrSessionRevoked), errors.Is(err, db.ErrNotFound):
			return models.EncryptedBlob{}, ErrUnauthorized
		}
		return models.EncryptedBlob{}, err
	}
	return stored, nil
}

// validatedBlob runs every blob write's shape checks and returns the row to
// store with the generation ceiling it was checked against.
func (s *SyncService) validatedBlob(accountID string, input PutBlobInput) (models.EncryptedBlob, int64, error) {
	if input.SchemaVersion <= 0 || input.Generation <= 0 || len(input.Ciphertext) == 0 {
		return models.EncryptedBlob{}, 0, ErrInvalidBlob
	}
	ceiling := maxAcceptableBlobGeneration(s.now())
	if input.Generation > ceiling {
		return models.EncryptedBlob{}, 0, ErrInvalidBlob
	}
	checksum := strings.ToLower(strings.TrimSpace(input.ChecksumSHA256))
	if !checksumPattern.MatchString(checksum) {
		return models.EncryptedBlob{}, 0, ErrInvalidBlob
	}
	if len(input.Ciphertext) > s.maxBlobBytes {
		return models.EncryptedBlob{}, 0, ErrInvalidBlob
	}
	sum := sha256.Sum256(input.Ciphertext)
	if hex.EncodeToString(sum[:]) != checksum {
		return models.EncryptedBlob{}, 0, ErrInvalidBlob
	}
	return models.EncryptedBlob{
		AccountID:      accountID,
		SchemaVersion:  input.SchemaVersion,
		Generation:     input.Generation,
		ChecksumSHA256: checksum,
		Ciphertext:     input.Ciphertext,
		CiphertextSize: len(input.Ciphertext),
		UpdatedAt:      s.now().UTC(),
	}, ceiling, nil
}

func (s *SyncService) GetBlob(ctx context.Context, accountID string) (models.EncryptedBlob, error) {
	blob, err := s.store.GetEncryptedBlob(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return models.EncryptedBlob{}, ErrBlobNotFound
		}
		return models.EncryptedBlob{}, err
	}

	return blob, nil
}

// PutRecoveryKeyPackage overwrites the account's wrapped recovery key after
// the step-up re-authentication; the store re-checks the verified state in
// the write's own transaction. For a package that differs from the stored
// one, the password is checked before the package is validated, so a wrong
// password answers as such whatever such a body holds. A TOTP-enrolled
// account must also present a current code: an overwrite replaces the
// owner's phrase-recovery path.
//
// A package equal to the stored one after normalization is answered with the
// stored row and needs no step-up (UnchangedRecoveryKeyPackage).
//
// A managed account has no password, so its session may store a first
// package but never replace one (ErrManagedRecoveryKeyOverwrite); a re-key
// goes through the bridge (ManagedBridgeService.ReplaceManagedRecoveryKeyPackage)
// after ovumcy-managed's own re-authentication.
func (s *SyncService) PutRecoveryKeyPackage(
	ctx context.Context,
	accountID string,
	stepUp StepUp,
	input PutRecoveryKeyPackageInput,
) (models.RecoveryKeyPackage, error) {
	recoveryKeyPackage := normalizeRecoveryKeyPackage(accountID, input)
	existing, unchanged, err := s.matchStoredRecoveryKeyPackage(ctx, recoveryKeyPackage)
	if err != nil {
		return models.RecoveryKeyPackage{}, err
	}
	if unchanged {
		return existing, nil
	}

	account, err := findStepUpAccount(ctx, s.store, accountID)
	if err != nil {
		return models.RecoveryKeyPackage{}, err
	}
	if account.Mode == "managed" {
		return s.putFirstManagedRecoveryKeyPackage(ctx, account, recoveryKeyPackage, stepUp)
	}
	if err := checkStepUpPassword(account, stepUp.CurrentPassword); err != nil {
		return models.RecoveryKeyPackage{}, err
	}

	if err := validateRecoveryKeyPackage(recoveryKeyPackage); err != nil {
		return models.RecoveryKeyPackage{}, err
	}

	recoveryKeyPackage.UpdatedAt = s.now().UTC()

	// After the package is validated, so a rejected body does not spend the
	// code's step.
	if err := verifyStepUpCode(ctx, s.totpCodes, account, stepUp.TOTPCode); err != nil {
		return models.RecoveryKeyPackage{}, err
	}

	stored, err := s.store.UpsertRecoveryKeyPackageForSession(
		ctx,
		recoveryKeyPackage,
		account.PasswordHash,
		account.TOTPEnabled,
		stepUp.SessionTokenHash,
	)
	if err != nil {
		return models.RecoveryKeyPackage{}, stepUpWriteError(err)
	}
	return stored, nil
}

// putFirstManagedRecoveryKeyPackage stores a managed account's first package
// in the transaction that re-checks the caller's session; any stored package,
// even one written concurrently, refuses the write.
func (s *SyncService) putFirstManagedRecoveryKeyPackage(
	ctx context.Context,
	account models.Account,
	recoveryKeyPackage models.RecoveryKeyPackage,
	stepUp StepUp,
) (models.RecoveryKeyPackage, error) {
	if err := validateRecoveryKeyPackage(recoveryKeyPackage); err != nil {
		return models.RecoveryKeyPackage{}, err
	}
	recoveryKeyPackage.UpdatedAt = s.now().UTC()
	// A managed account cannot enroll TOTP (no password passes its step-up);
	// should one ever hold it, the code is still required.
	if err := verifyStepUpCode(ctx, s.totpCodes, account, stepUp.TOTPCode); err != nil {
		return models.RecoveryKeyPackage{}, err
	}

	stored, err := s.store.InsertRecoveryKeyPackageForSession(ctx, recoveryKeyPackage, stepUp.SessionTokenHash)
	if errors.Is(err, db.ErrConflict) {
		return models.RecoveryKeyPackage{}, ErrManagedRecoveryKeyOverwrite
	}
	if err != nil {
		return models.RecoveryKeyPackage{}, stepUpWriteError(err)
	}
	return stored, nil
}

// UnchangedRecoveryKeyPackage reports whether input, normalized as
// PutRecoveryKeyPackage normalizes it, equals the stored package, and returns
// the stored row if so. Such a re-put needs no step-up: it writes nothing and
// discloses nothing GET /sync/recovery-key does not, and clients send it with
// every upload. The transport answers it before charging the step-up bucket.
func (s *SyncService) UnchangedRecoveryKeyPackage(
	ctx context.Context,
	accountID string,
	input PutRecoveryKeyPackageInput,
) (models.RecoveryKeyPackage, bool, error) {
	return s.matchStoredRecoveryKeyPackage(ctx, normalizeRecoveryKeyPackage(accountID, input))
}

// validateRecoveryKeyPackage is the one shape check every recovery-key write
// runs on a normalized package: the session route and the managed bridge
// re-key accept exactly the same packages.
func validateRecoveryKeyPackage(recoveryKeyPackage models.RecoveryKeyPackage) error {
	if recoveryKeyPackage.Algorithm != "xchacha20poly1305" || recoveryKeyPackage.KDF != "bip39_seed_hkdf_sha256" {
		return ErrInvalidRecoveryPackage
	}
	if recoveryKeyPackage.MnemonicWordCount != 12 {
		return ErrInvalidRecoveryPackage
	}
	wrapNonceHex := recoveryKeyPackage.WrapNonceHex
	if len(wrapNonceHex) != 48 || !lowercaseHexPattern.MatchString(wrapNonceHex) {
		return ErrInvalidRecoveryPackage
	}
	// 32-byte master key + 16-byte Poly1305 tag. Rows stored under the older
	// at-least-64 rule still read, and PutRecoveryKeyPackage's unchanged check
	// runs first, so their identical session re-put still succeeds.
	wrappedMasterKeyHex := recoveryKeyPackage.WrappedMasterKeyHex
	if len(wrappedMasterKeyHex) != 96 || !lowercaseHexPattern.MatchString(wrappedMasterKeyHex) {
		return ErrInvalidRecoveryPackage
	}
	phraseFingerprintHex := recoveryKeyPackage.PhraseFingerprintHex
	if len(phraseFingerprintHex) != 16 || !lowercaseHexPattern.MatchString(phraseFingerprintHex) {
		return ErrInvalidRecoveryPackage
	}
	return nil
}

func normalizeRecoveryKeyPackage(accountID string, input PutRecoveryKeyPackageInput) models.RecoveryKeyPackage {
	return models.RecoveryKeyPackage{
		AccountID:            accountID,
		Algorithm:            strings.TrimSpace(strings.ToLower(input.Algorithm)),
		KDF:                  strings.TrimSpace(strings.ToLower(input.KDF)),
		MnemonicWordCount:    input.MnemonicWordCount,
		WrapNonceHex:         strings.TrimSpace(strings.ToLower(input.WrapNonceHex)),
		WrappedMasterKeyHex:  strings.TrimSpace(strings.ToLower(input.WrappedMasterKeyHex)),
		PhraseFingerprintHex: strings.TrimSpace(strings.ToLower(input.PhraseFingerprintHex)),
	}
}

func (s *SyncService) matchStoredRecoveryKeyPackage(
	ctx context.Context,
	candidate models.RecoveryKeyPackage,
) (models.RecoveryKeyPackage, bool, error) {
	existing, err := s.store.GetRecoveryKeyPackage(ctx, candidate.AccountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return models.RecoveryKeyPackage{}, false, nil
		}
		return models.RecoveryKeyPackage{}, false, err
	}
	// Compared whole, so a field added to the package can never be skipped by
	// the no-op check.
	content := existing
	content.UpdatedAt = time.Time{}
	if content != candidate {
		return models.RecoveryKeyPackage{}, false, nil
	}
	return existing, true, nil
}

func (s *SyncService) GetRecoveryKeyPackage(
	ctx context.Context,
	accountID string,
) (models.RecoveryKeyPackage, error) {
	recoveryKeyPackage, err := s.store.GetRecoveryKeyPackage(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return models.RecoveryKeyPackage{}, ErrRecoveryPackageNotFound
		}
		return models.RecoveryKeyPackage{}, err
	}

	return recoveryKeyPackage, nil
}
