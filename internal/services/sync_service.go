package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

var ErrInvalidDevice = errors.New("invalid_device")
var ErrTooManyDevices = errors.New("too_many_devices")
var ErrDeviceNotFound = errors.New("device_not_found")
var ErrInvalidBlob = errors.New("invalid_blob")
var ErrBlobNotFound = errors.New("blob_not_found")
var ErrStaleGeneration = errors.New("stale_generation")
var ErrInvalidRecoveryPackage = errors.New("invalid_recovery_package")
var ErrRecoveryPackageNotFound = errors.New("recovery_package_not_found")

var checksumPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var lowercaseHexPattern = regexp.MustCompile(`^[a-f0-9]+$`)

// maxBlobGeneration rejects a blob generation within 2^32 of the int64 ceiling.
// The client derives generation from a millisecond timestamp (ovumcy-app's
// nextRemoteGeneration), which is astronomically far below this bound, so
// legitimate writes are never affected. Without the cap, a single crafted write
// at math.MaxInt64 would strand the blob at a value that no future strictly-
// greater write could reach — the UpsertEncryptedBlob CAS only accepts a higher
// generation — permanently locking the owner out of their own blob. The 2^32
// reserve keeps ample headroom for future increments below the bound.
const maxBlobGeneration = math.MaxInt64 - (1 << 32)

type SyncService struct {
	store        *db.Store
	maxDevices   int
	maxBlobBytes int
	now          func() time.Time
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
	deviceID = strings.TrimSpace(deviceID)
	deviceLabel = strings.TrimSpace(deviceLabel)
	if len(deviceID) < 8 || len(deviceLabel) < 2 {
		return models.Device{}, ErrInvalidDevice
	}

	now := s.now().UTC()
	// Atomic ceiling in the repository: the WHERE sub-select rejects an
	// attach that would exceed maxDevices in the same statement that
	// inserts, so we don't count-then-write here. Concurrent attaches that
	// all read the same count would otherwise each add a row and push the
	// account past its limit.
	device, err := s.store.UpsertDevice(ctx, models.Device{
		DeviceID:    deviceID,
		AccountID:   accountID,
		DeviceLabel: deviceLabel,
		CreatedAt:   now,
		LastSeenAt:  now,
	}, s.maxDevices)
	if err != nil {
		if errors.Is(err, db.ErrDeviceLimitReached) {
			return models.Device{}, ErrTooManyDevices
		}
		return models.Device{}, err
	}

	return device, nil
}

// ListDevices returns every device attached to the account, account-scoped.
func (s *SyncService) ListDevices(ctx context.Context, accountID string) ([]models.Device, error) {
	return s.store.ListDevicesForAccount(ctx, accountID)
}

// RemoveDevice detaches one device from the account so its slot is freed. The
// delete is account-scoped in the query (no IDOR), and removing a device does
// not touch sessions — sessions are not device-bound. Returns ErrInvalidDevice
// for an empty id and ErrDeviceNotFound when the account has no such device.
func (s *SyncService) RemoveDevice(ctx context.Context, accountID string, deviceID string) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return ErrInvalidDevice
	}

	if err := s.store.DeleteDevice(ctx, accountID, deviceID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrDeviceNotFound
		}
		return err
	}

	return nil
}

func (s *SyncService) PutBlob(
	ctx context.Context,
	accountID string,
	input PutBlobInput,
) (models.EncryptedBlob, error) {
	if input.SchemaVersion <= 0 || input.Generation <= 0 || input.Generation > maxBlobGeneration || len(input.Ciphertext) == 0 {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}
	if !checksumPattern.MatchString(strings.ToLower(strings.TrimSpace(input.ChecksumSHA256))) {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}
	if len(input.Ciphertext) > s.maxBlobBytes {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}
	sum := sha256.Sum256(input.Ciphertext)
	if hex.EncodeToString(sum[:]) != strings.ToLower(strings.TrimSpace(input.ChecksumSHA256)) {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}

	blob := models.EncryptedBlob{
		AccountID:      accountID,
		SchemaVersion:  input.SchemaVersion,
		Generation:     input.Generation,
		ChecksumSHA256: strings.ToLower(strings.TrimSpace(input.ChecksumSHA256)),
		Ciphertext:     input.Ciphertext,
		CiphertextSize: len(input.Ciphertext),
		UpdatedAt:      s.now().UTC(),
	}

	// Atomic CAS in the repository: the WHERE excluded.generation >
	// encrypted_blobs.generation guard rejects concurrent writers that
	// passed the same baseline, so we don't read-then-write here.
	stored, err := s.store.UpsertEncryptedBlob(ctx, blob)
	if err != nil {
		if errors.Is(err, db.ErrStaleGeneration) {
			return models.EncryptedBlob{}, ErrStaleGeneration
		}
		return models.EncryptedBlob{}, err
	}
	return stored, nil
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

func (s *SyncService) PutRecoveryKeyPackage(
	ctx context.Context,
	accountID string,
	input PutRecoveryKeyPackageInput,
) (models.RecoveryKeyPackage, error) {
	algorithm := strings.TrimSpace(strings.ToLower(input.Algorithm))
	kdf := strings.TrimSpace(strings.ToLower(input.KDF))
	wrapNonceHex := strings.TrimSpace(strings.ToLower(input.WrapNonceHex))
	wrappedMasterKeyHex := strings.TrimSpace(strings.ToLower(input.WrappedMasterKeyHex))
	phraseFingerprintHex := strings.TrimSpace(strings.ToLower(input.PhraseFingerprintHex))

	if algorithm != "xchacha20poly1305" || kdf != "bip39_seed_hkdf_sha256" {
		return models.RecoveryKeyPackage{}, ErrInvalidRecoveryPackage
	}
	if input.MnemonicWordCount != 12 {
		return models.RecoveryKeyPackage{}, ErrInvalidRecoveryPackage
	}
	if len(wrapNonceHex) != 48 || !lowercaseHexPattern.MatchString(wrapNonceHex) {
		return models.RecoveryKeyPackage{}, ErrInvalidRecoveryPackage
	}
	if len(wrappedMasterKeyHex) < 64 || len(wrappedMasterKeyHex)%2 != 0 || !lowercaseHexPattern.MatchString(wrappedMasterKeyHex) {
		return models.RecoveryKeyPackage{}, ErrInvalidRecoveryPackage
	}
	if len(phraseFingerprintHex) != 16 || !lowercaseHexPattern.MatchString(phraseFingerprintHex) {
		return models.RecoveryKeyPackage{}, ErrInvalidRecoveryPackage
	}

	recoveryKeyPackage := models.RecoveryKeyPackage{
		AccountID:            accountID,
		Algorithm:            algorithm,
		KDF:                  kdf,
		MnemonicWordCount:    input.MnemonicWordCount,
		WrapNonceHex:         wrapNonceHex,
		WrappedMasterKeyHex:  wrappedMasterKeyHex,
		PhraseFingerprintHex: phraseFingerprintHex,
		UpdatedAt:            s.now().UTC(),
	}

	return s.store.UpsertRecoveryKeyPackage(ctx, recoveryKeyPackage)
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
