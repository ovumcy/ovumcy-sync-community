package services

import (
	"context"
	"errors"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

var ErrInvalidRegistrationInput = errors.New("invalid_registration_input")
var ErrRegistrationFailed = errors.New("registration_failed")
var ErrInvalidCredentials = errors.New("invalid_credentials")
var ErrUnauthorized = errors.New("unauthorized")

type AuthService struct {
	store      *db.Store
	sessionTTL time.Duration
	now        func() time.Time
}

type AuthResult struct {
	AccountID        string    `json:"account_id"`
	SessionToken     string    `json:"session_token"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
}

func NewAuthService(store *db.Store, sessionTTL time.Duration) *AuthService {
	return &AuthService{
		store:      store,
		sessionTTL: sessionTTL,
		now:        time.Now,
	}
}

func (s *AuthService) Register(ctx context.Context, login string, password string) (AuthResult, error) {
	normalizedLogin := security.NormalizeLogin(login)
	if !security.ValidateLogin(normalizedLogin) {
		return AuthResult{}, ErrInvalidRegistrationInput
	}

	passwordHash, err := security.HashPassword(password)
	if err != nil {
		if errors.Is(err, security.ErrWeakPassword) {
			return AuthResult{}, ErrInvalidRegistrationInput
		}
		return AuthResult{}, err
	}

	accountID, err := security.NewIdentifier()
	if err != nil {
		return AuthResult{}, err
	}

	now := s.now().UTC()
	_, err = s.store.CreateAccount(ctx, models.Account{
		ID:           accountID,
		Login:        normalizedLogin,
		PasswordHash: passwordHash,
		Mode:         "self_hosted",
		PremiumActive: false,
		CreatedAt:    now,
	})
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			return AuthResult{}, ErrRegistrationFailed
		}
		return AuthResult{}, err
	}

	return s.createSession(ctx, accountID, now)
}

func (s *AuthService) Login(ctx context.Context, login string, password string) (AuthResult, error) {
	account, err := s.store.FindAccountByLogin(ctx, security.NormalizeLogin(login))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return AuthResult{}, ErrInvalidCredentials
		}
		return AuthResult{}, err
	}

	if err := security.ComparePasswordHash(account.PasswordHash, password); err != nil {
		return AuthResult{}, ErrInvalidCredentials
	}

	return s.createSession(ctx, account.ID, s.now().UTC())
}

func (s *AuthService) Authenticate(ctx context.Context, sessionToken string) (models.Account, error) {
	if sessionToken == "" {
		return models.Account{}, ErrUnauthorized
	}

	session, err := s.store.FindSessionByTokenHash(ctx, security.HashToken(sessionToken))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return models.Account{}, ErrUnauthorized
		}
		return models.Account{}, err
	}

	now := s.now().UTC()
	if !session.ExpiresAt.After(now) {
		return models.Account{}, ErrUnauthorized
	}

	_ = s.store.TouchSession(ctx, session.ID, now)

	account, err := s.store.FindAccountByID(ctx, session.AccountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return models.Account{}, ErrUnauthorized
		}
		return models.Account{}, err
	}

	return account, nil
}

func (s *AuthService) RevokeSession(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return ErrUnauthorized
	}

	if err := s.store.DeleteSessionByTokenHash(ctx, security.HashToken(sessionToken)); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}

	return nil
}

func (s *AuthService) CreateSessionForAccount(
	ctx context.Context,
	accountID string,
) (AuthResult, error) {
	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return AuthResult{}, ErrUnauthorized
		}
		return AuthResult{}, err
	}

	return s.createSession(ctx, account.ID, s.now().UTC())
}

func (s *AuthService) createSession(
	ctx context.Context,
	accountID string,
	now time.Time,
) (AuthResult, error) {
	sessionID, err := security.NewIdentifier()
	if err != nil {
		return AuthResult{}, err
	}

	plainToken, tokenHash, err := security.NewOpaqueToken()
	if err != nil {
		return AuthResult{}, err
	}

	expiresAt := now.Add(s.sessionTTL)
	_, err = s.store.CreateSession(ctx, models.Session{
		ID:         sessionID,
		AccountID:  accountID,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		return AuthResult{}, err
	}

	return AuthResult{
		AccountID:        accountID,
		SessionToken:     plainToken,
		SessionExpiresAt: expiresAt,
	}, nil
}
