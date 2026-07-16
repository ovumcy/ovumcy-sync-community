package services

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

var ErrInvalidManagedAccount = errors.New("invalid_managed_account")

var managedAccountIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{7,127}$`)

type ManagedBridgeService struct {
	store *db.Store
	auth  *AuthService
	now   func() time.Time
}

func NewManagedBridgeService(store *db.Store, auth *AuthService) *ManagedBridgeService {
	return &ManagedBridgeService{
		store: store,
		auth:  auth,
		now:   time.Now,
	}
}

func (s *ManagedBridgeService) CreateManagedSession(
	ctx context.Context,
	accountID string,
) (AuthResult, error) {
	accountID = strings.TrimSpace(strings.ToLower(accountID))
	if !managedAccountIDPattern.MatchString(accountID) {
		return AuthResult{}, ErrInvalidManagedAccount
	}

	existingAccount, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return AuthResult{}, err
	}
	if err == nil && existingAccount.Mode != "managed" {
		return AuthResult{}, ErrInvalidManagedAccount
	}

	now := s.now().UTC()
	_, err = s.store.UpsertManagedAccount(ctx, models.Account{
		ID:            accountID,
		Login:         "managed:" + accountID,
		PasswordHash:  "managed_service_only",
		Mode:          "managed",
		PremiumActive: true,
		CreatedAt:     existingOrCreatedAt(existingAccount, now),
	})
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			return AuthResult{}, ErrInvalidManagedAccount
		}
		return AuthResult{}, err
	}

	return s.auth.CreateSessionForAccount(ctx, accountID)
}

// PurgeManagedAccount permanently erases the managed account and every row
// this server holds for it — sessions, devices, the encrypted sync blob, the
// wrapped recovery-key package, pending password-reset tokens, and TOTP
// challenges — via Store.DeleteAccount's single transaction. It is the
// sync-plane half of managed-cloud account deletion: the separate managed
// service calls it before purging its own database so no ciphertext is ever
// orphaned here.
//
// The id is matched raw against accounts.id after the same normalization and
// pattern gate as CreateManagedSession — the "managed:" namespace lives only
// in the login column, never in the id. Only mode=managed accounts are
// erasable through this path: a self-hosted account whose id collides is
// refused with ErrInvalidManagedAccount and left untouched, so the bridge
// credential can never erase a self-hosted user's data.
//
// Idempotent: an account that never existed or is already gone (including a
// concurrent-delete race) returns nil, so the managed caller can safely retry
// after a dropped response.
func (s *ManagedBridgeService) PurgeManagedAccount(
	ctx context.Context,
	accountID string,
) error {
	accountID = strings.TrimSpace(strings.ToLower(accountID))
	if !managedAccountIDPattern.MatchString(accountID) {
		return ErrInvalidManagedAccount
	}

	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil
		}
		return err
	}
	if account.Mode != "managed" {
		return ErrInvalidManagedAccount
	}

	if err := s.store.DeleteAccount(ctx, accountID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil
		}
		return err
	}

	return nil
}

func existingOrCreatedAt(account models.Account, fallback time.Time) time.Time {
	if !account.CreatedAt.IsZero() {
		return account.CreatedAt
	}
	return fallback
}
