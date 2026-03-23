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

func existingOrCreatedAt(account models.Account, fallback time.Time) time.Time {
	if !account.CreatedAt.IsZero() {
		return account.CreatedAt
	}
	return fallback
}
