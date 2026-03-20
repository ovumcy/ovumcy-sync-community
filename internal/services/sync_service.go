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
var ErrTooManyDevices = errors.New("too_many_devices")
var ErrInvalidBlob = errors.New("invalid_blob")
var ErrBlobNotFound = errors.New("blob_not_found")
var ErrStaleGeneration = errors.New("stale_generation")

var checksumPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type SyncService struct {
	store      *db.Store
	maxDevices int
	now        func() time.Time
}

type PutBlobInput struct {
	SchemaVersion  int
	Generation     int64
	ChecksumSHA256 string
	Ciphertext     []byte
}

func NewSyncService(store *db.Store, maxDevices int) *SyncService {
	return &SyncService{
		store:      store,
		maxDevices: maxDevices,
		now:        time.Now,
	}
}

func (s *SyncService) Capabilities() models.CapabilityDocument {
	return models.CapabilityDocument{
		Mode:              "self_hosted",
		SyncEnabled:       true,
		PremiumActive:     false,
		RecoverySupported: false,
		PushSupported:     false,
		PortalSupported:   false,
		AdvancedInsights:  false,
		MaxDevices:        s.maxDevices,
		MaxBlobBytes:      16 << 20,
	}
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
	if _, err := s.store.FindDevice(ctx, accountID, deviceID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			count, countErr := s.store.CountDevicesForAccount(ctx, accountID)
			if countErr != nil {
				return models.Device{}, countErr
			}
			if count >= s.maxDevices {
				return models.Device{}, ErrTooManyDevices
			}
		} else {
			return models.Device{}, err
		}
	}

	return s.store.UpsertDevice(ctx, models.Device{
		DeviceID:    deviceID,
		AccountID:   accountID,
		DeviceLabel: deviceLabel,
		CreatedAt:   now,
		LastSeenAt:  now,
	})
}

func (s *SyncService) PutBlob(
	ctx context.Context,
	accountID string,
	input PutBlobInput,
) (models.EncryptedBlob, error) {
	if input.SchemaVersion <= 0 || input.Generation <= 0 || len(input.Ciphertext) == 0 {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}
	if !checksumPattern.MatchString(strings.ToLower(strings.TrimSpace(input.ChecksumSHA256))) {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}
	if int64(len(input.Ciphertext)) > s.Capabilities().MaxBlobBytes {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}
	sum := sha256.Sum256(input.Ciphertext)
	if hex.EncodeToString(sum[:]) != strings.ToLower(strings.TrimSpace(input.ChecksumSHA256)) {
		return models.EncryptedBlob{}, ErrInvalidBlob
	}

	existingBlob, err := s.store.GetEncryptedBlob(ctx, accountID)
	if err == nil && input.Generation <= existingBlob.Generation {
		return models.EncryptedBlob{}, ErrStaleGeneration
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return models.EncryptedBlob{}, err
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

	return s.store.UpsertEncryptedBlob(ctx, blob)
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
