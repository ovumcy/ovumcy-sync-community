package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

var ErrInvalidRegistrationInput = errors.New("invalid_registration_input")
var ErrRegistrationFailed = errors.New("registration_failed")
var ErrInvalidCredentials = errors.New("invalid_credentials")
var ErrUnauthorized = errors.New("unauthorized")
var ErrInvalidCurrentPassword = errors.New("invalid_current_password")
var ErrNewPasswordMustDiffer = errors.New("new_password_must_differ")
var ErrWeakNewPassword = errors.New("weak_new_password")
var ErrInvalidRecoveryCredentials = errors.New("invalid_recovery_credentials")
var ErrInvalidResetToken = errors.New("invalid_reset_token")

// PasswordResetTokenTTL is how long an issued reset token stays valid.
// 30 minutes is short enough that a leaked token has bounded value and long
// enough that an owner can move between the reset email/SMS surface (the
// operator-provided out-of-band channel) and the new-password screen.
const PasswordResetTokenTTL = 30 * time.Minute

// TOTPChallengeIssuer is implemented by services that can mint a TOTP login
// challenge after a successful password verification. AuthService delegates
// to it instead of importing the TOTPService directly so the dependency
// graph stays one-directional (totp -> auth -> store).
type TOTPChallengeIssuer interface {
	IssueChallenge(ctx context.Context, accountID string) (challengeID string, expiresAt time.Time, err error)
}

type AuthService struct {
	store          *db.Store
	sessionTTL     time.Duration
	now            func() time.Time
	totpChallenges TOTPChallengeIssuer
}

type AuthResult struct {
	AccountID        string    `json:"account_id"`
	SessionToken     string    `json:"session_token"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
	// RecoveryCode is the plaintext account-level recovery code. It is set
	// only on `Register` responses (the single moment we surface it). Login
	// and managed-bridge sessions leave this field empty.
	RecoveryCode string `json:"recovery_code,omitempty"`
	// TOTPChallenge is non-nil ONLY when password verification succeeded but
	// the account has TOTP enabled. In that case the session token fields are
	// empty and the caller must complete `POST /auth/totp/challenge` with
	// this challenge id before any session is issued.
	TOTPChallenge *AuthTOTPChallenge `json:"totp_challenge,omitempty"`
}

// AuthTOTPChallenge is the wire shape of a pending TOTP login second factor.
// The challenge id is single-use and short-lived (`TOTPChallengeTTL`).
type AuthTOTPChallenge struct {
	ChallengeID        string    `json:"challenge_id"`
	ChallengeExpiresAt time.Time `json:"challenge_expires_at"`
}

// PasswordResetResult is returned from ResetPassword. It carries the newly
// rotated recovery code so the owner sees the new one immediately after
// completing reset.
type PasswordResetResult struct {
	RecoveryCode string `json:"recovery_code"`
}

// ForgotPasswordResult is returned from a successful ForgotPassword call.
// The plaintext reset token must be carried to the new-password screen by
// the caller; it is never persisted on the server in plaintext.
type ForgotPasswordResult struct {
	ResetToken          string    `json:"reset_token"`
	ResetTokenExpiresAt time.Time `json:"reset_token_expires_at"`
}

func NewAuthService(store *db.Store, sessionTTL time.Duration) *AuthService {
	return &AuthService{
		store:      store,
		sessionTTL: sessionTTL,
		now:        time.Now,
	}
}

// AttachTOTPChallengeIssuer wires the TOTP login second-factor flow. When
// non-nil and the account has TOTP enabled, Login returns a TOTP challenge
// instead of a session token. When nil (the default), Login on a TOTP-enabled
// account fails closed with ErrTOTPNotConfigured instead of issuing a
// password-only session, so an enrolled account is never silently downgraded
// to single-factor auth on a server with no field encryption key configured.
// Accounts without TOTP enabled are unaffected and log in normally.
func (s *AuthService) AttachTOTPChallengeIssuer(issuer TOTPChallengeIssuer) {
	s.totpChallenges = issuer
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

	recoveryCode, recoveryCodeHash, err := security.NewRecoveryCode()
	if err != nil {
		return AuthResult{}, err
	}

	accountID, err := security.NewIdentifier()
	if err != nil {
		return AuthResult{}, err
	}

	now := s.now().UTC()
	_, err = s.store.CreateAccount(ctx, models.Account{
		ID:               accountID,
		Login:            normalizedLogin,
		PasswordHash:     passwordHash,
		RecoveryCodeHash: recoveryCodeHash,
		Mode:             "self_hosted",
		PremiumActive:    false,
		CreatedAt:        now,
	})
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			return AuthResult{}, ErrRegistrationFailed
		}
		return AuthResult{}, err
	}

	result, err := s.createSession(ctx, accountID, now)
	if err != nil {
		return AuthResult{}, err
	}
	result.RecoveryCode = recoveryCode
	return result, nil
}

func (s *AuthService) Login(ctx context.Context, login string, password string) (AuthResult, error) {
	account, err := s.store.FindAccountByLogin(ctx, security.NormalizeLogin(login))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// Equalize timing so an attacker cannot distinguish an unknown
			// login from a wrong password by measuring response latency.
			equalizePasswordTiming(password)
			return AuthResult{}, ErrInvalidCredentials
		}
		return AuthResult{}, err
	}

	if err := security.ComparePasswordHash(account.PasswordHash, password); err != nil {
		return AuthResult{}, ErrInvalidCredentials
	}

	if account.TOTPEnabled {
		if s.totpChallenges == nil {
			// Fail closed. The account opted into TOTP 2FA, but this server has
			// no field encryption key configured, so the second factor cannot
			// be issued or verified. Refuse the login instead of silently
			// downgrading an enrolled account to password-only auth. A
			// locked-out owner recovers through the recovery-code password
			// reset, which clears TOTP (see ResetPassword), or the operator
			// restores the key.
			return AuthResult{}, ErrTOTPNotConfigured
		}
		challengeID, expiresAt, issueErr := s.totpChallenges.IssueChallenge(ctx, account.ID)
		if issueErr != nil {
			return AuthResult{}, issueErr
		}
		return AuthResult{
			AccountID: account.ID,
			TOTPChallenge: &AuthTOTPChallenge{
				ChallengeID:        challengeID,
				ChallengeExpiresAt: expiresAt,
			},
		}, nil
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

// ChangePassword verifies the caller's current password, rehashes the new
// password, and revokes every session belonging to the account except the one
// used for this request. The caller-side session remains active.
//
// currentSessionTokenHash is the SHA256(token) of the caller's bearer token;
// it is preserved while every other session for the account is deleted. This
// mirrors ovumcy-web's "revoke all sessions except current" invariant on
// password change.
func (s *AuthService) ChangePassword(
	ctx context.Context,
	accountID string,
	currentSessionTokenHash string,
	currentPassword string,
	newPassword string,
) error {
	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}

	if err := security.ComparePasswordHash(account.PasswordHash, currentPassword); err != nil {
		return ErrInvalidCurrentPassword
	}

	if currentPassword == newPassword {
		return ErrNewPasswordMustDiffer
	}

	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		if errors.Is(err, security.ErrWeakPassword) {
			return ErrWeakNewPassword
		}
		return err
	}

	if err := s.store.UpdateAccountPasswordHash(ctx, accountID, newHash); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}

	if err := s.store.DeleteSessionsForAccountExcept(ctx, accountID, currentSessionTokenHash); err != nil {
		return err
	}

	if err := s.store.DeletePasswordResetTokensForAccount(ctx, accountID); err != nil {
		return err
	}

	return nil
}

// ForgotPassword verifies an account-level recovery code and issues a
// short-lived reset token. The recovery code is single-use semantically: a
// successful ResetPassword call rotates it to a fresh code.
//
// Errors are deliberately generic (`ErrInvalidRecoveryCredentials`) for
// unknown login, wrong recovery code, and accounts created before recovery
// codes existed (empty stored hash). This keeps the surface enumeration-safe.
func (s *AuthService) ForgotPassword(
	ctx context.Context,
	login string,
	recoveryCode string,
) (ForgotPasswordResult, error) {
	normalizedLogin := security.NormalizeLogin(login)
	normalizedCode := security.NormalizeRecoveryCode(recoveryCode)

	account, err := s.store.FindAccountByLogin(ctx, normalizedLogin)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// Equalize timing so an attacker cannot tell an unknown login
			// apart from a wrong recovery code by measuring response latency.
			equalizePasswordTiming(normalizedCode)
			return ForgotPasswordResult{}, ErrInvalidRecoveryCredentials
		}
		return ForgotPasswordResult{}, err
	}

	if account.RecoveryCodeHash == "" {
		// Pre-migration accounts have no recovery code set. Burn the same
		// bcrypt cost so the surface stays indistinguishable from "wrong
		// recovery code on an account that does have one".
		equalizePasswordTiming(normalizedCode)
		return ForgotPasswordResult{}, ErrInvalidRecoveryCredentials
	}

	if err := security.CompareRecoveryCodeHash(account.RecoveryCodeHash, normalizedCode); err != nil {
		return ForgotPasswordResult{}, ErrInvalidRecoveryCredentials
	}

	plainToken, tokenHash, err := security.NewOpaqueToken()
	if err != nil {
		return ForgotPasswordResult{}, err
	}

	now := s.now().UTC()
	expiresAt := now.Add(PasswordResetTokenTTL)
	if err := s.store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: account.ID,
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}); err != nil {
		return ForgotPasswordResult{}, err
	}

	return ForgotPasswordResult{
		ResetToken:          plainToken,
		ResetTokenExpiresAt: expiresAt,
	}, nil
}

// ResetPassword consumes a reset token and rotates both password and recovery
// code. On success: token is deleted, every existing session of the account is
// revoked, and a freshly generated recovery code is returned in plaintext.
func (s *AuthService) ResetPassword(
	ctx context.Context,
	resetToken string,
	newPassword string,
) (PasswordResetResult, error) {
	if strings.TrimSpace(resetToken) == "" {
		return PasswordResetResult{}, ErrInvalidResetToken
	}

	tokenRecord, err := s.store.ConsumePasswordResetToken(ctx, security.HashToken(resetToken), s.now().UTC())
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return PasswordResetResult{}, ErrInvalidResetToken
		}
		return PasswordResetResult{}, err
	}

	newPasswordHash, err := security.HashPassword(newPassword)
	if err != nil {
		if errors.Is(err, security.ErrWeakPassword) {
			return PasswordResetResult{}, ErrWeakNewPassword
		}
		return PasswordResetResult{}, err
	}

	plainRecovery, recoveryHash, err := security.NewRecoveryCode()
	if err != nil {
		return PasswordResetResult{}, err
	}

	if err := s.store.UpdateAccountPasswordAndRecoveryHash(
		ctx,
		tokenRecord.AccountID,
		newPasswordHash,
		recoveryHash,
	); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return PasswordResetResult{}, ErrInvalidResetToken
		}
		return PasswordResetResult{}, err
	}

	// Recovery-code-driven reset is also the documented fallback for a lost
	// authenticator app: proving control of the account-level recovery code
	// disables 2FA so the owner is not permanently locked out. The recovery
	// code is the catch-all credential — anyone who can prove possession of
	// it already has full account control, so keeping TOTP enabled past
	// reset would only convert a recoverable situation into a lock-out.
	if err := s.store.UpdateTOTPSecretAndEnabled(
		ctx,
		tokenRecord.AccountID,
		"",
		false,
	); err != nil && !errors.Is(err, db.ErrNotFound) {
		return PasswordResetResult{}, err
	}
	if err := s.store.DeleteTOTPChallengesForAccount(ctx, tokenRecord.AccountID); err != nil {
		return PasswordResetResult{}, err
	}

	if err := s.store.DeleteAllSessionsForAccount(ctx, tokenRecord.AccountID); err != nil {
		return PasswordResetResult{}, err
	}

	if err := s.store.DeletePasswordResetTokensForAccount(ctx, tokenRecord.AccountID); err != nil {
		return PasswordResetResult{}, err
	}

	return PasswordResetResult{RecoveryCode: plainRecovery}, nil
}

// RegenerateRecoveryCode rotates the account-level recovery code. The owner
// must re-confirm their current password; this guards against accidental or
// hijacked rotations that would silently lock the legitimate owner out of the
// recovery surface. Existing sessions and reset tokens are left untouched.
func (s *AuthService) RegenerateRecoveryCode(
	ctx context.Context,
	accountID string,
	currentPassword string,
) (string, error) {
	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return "", ErrUnauthorized
		}
		return "", err
	}

	if err := security.ComparePasswordHash(account.PasswordHash, currentPassword); err != nil {
		return "", ErrInvalidCurrentPassword
	}

	plainRecovery, recoveryHash, err := security.NewRecoveryCode()
	if err != nil {
		return "", err
	}

	if err := s.store.UpdateAccountRecoveryCodeHash(ctx, accountID, recoveryHash); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return "", ErrUnauthorized
		}
		return "", err
	}

	return plainRecovery, nil
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
