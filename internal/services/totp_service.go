package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

var (
	ErrTOTPNotConfigured     = errors.New("totp_not_configured")
	ErrTOTPAlreadyEnabled    = errors.New("totp_already_enabled")
	ErrTOTPSecretEncrypt     = errors.New("totp_secret_encrypt")
	ErrTOTPSecretDecrypt     = errors.New("totp_secret_decrypt")
	ErrTOTPInvalidCode       = errors.New("totp_invalid_code")
	ErrTOTPReplayed          = errors.New("totp_replayed")
	ErrTOTPChallengeInvalid  = errors.New("totp_challenge_invalid")
	ErrTOTPChallengeRequired = errors.New("totp_challenge_required")
)

// TOTPChallengeTTL is how long a login-second-factor challenge remains
// usable. 5 minutes is long enough that an owner has time to open their
// authenticator app and type the code, short enough that a leaked
// challenge ID is bounded.
const TOTPChallengeTTL = 5 * time.Minute

// TOTPService owns enrollment, verification, disable, and the login
// second-factor challenge flow. The encrypted secret is stored on the
// account row; the AEAD key comes from the server config.
type TOTPService struct {
	store      *db.Store
	auth       *AuthService
	secretKey  []byte
	issuer     string
	now        func() time.Time
	newSecret  func() ([]byte, error)
}

func NewTOTPService(
	store *db.Store,
	auth *AuthService,
	secretKey []byte,
	issuer string,
) *TOTPService {
	return &TOTPService{
		store:     store,
		auth:      auth,
		secretKey: secretKey,
		issuer:    issuer,
		now:       time.Now,
		newSecret: security.NewTOTPSecret,
	}
}

// Configured returns false when the server has no field encryption key set,
// in which case all TOTP endpoints must return ErrTOTPNotConfigured rather
// than silently failing to encrypt the secret.
func (s *TOTPService) Configured() bool {
	return len(s.secretKey) > 0
}

// TOTPEnrollmentStart is returned from StartEnrollment. The plaintext secret
// is surfaced for manual entry; the provisioning URI is for QR code rendering.
type TOTPEnrollmentStart struct {
	SecretBase32     string `json:"secret_base32"`
	ProvisioningURI  string `json:"provisioning_uri"`
}

// StartEnrollment verifies the current password, generates a fresh TOTP
// secret, encrypts it under the field key bound to the account id, and
// stores it with totp_enabled=false. A subsequent CompleteEnrollment call
// must verify a code from the user's authenticator app before TOTP is
// actually treated as enabled on login.
//
// If TOTP is already enabled the caller must Disable first.
func (s *TOTPService) StartEnrollment(
	ctx context.Context,
	accountID string,
	currentPassword string,
) (TOTPEnrollmentStart, error) {
	if !s.Configured() {
		return TOTPEnrollmentStart{}, ErrTOTPNotConfigured
	}

	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return TOTPEnrollmentStart{}, ErrUnauthorized
		}
		return TOTPEnrollmentStart{}, err
	}

	if account.TOTPEnabled {
		return TOTPEnrollmentStart{}, ErrTOTPAlreadyEnabled
	}

	if err := security.ComparePasswordHash(account.PasswordHash, currentPassword); err != nil {
		return TOTPEnrollmentStart{}, ErrInvalidCurrentPassword
	}

	secret, err := s.newSecret()
	if err != nil {
		return TOTPEnrollmentStart{}, err
	}

	encrypted, err := security.EncryptField(string(secret), s.secretKey, aadForTOTPSecret(accountID))
	if err != nil {
		return TOTPEnrollmentStart{}, fmt.Errorf("%w: %v", ErrTOTPSecretEncrypt, err)
	}

	if err := s.store.UpdateTOTPSecretAndEnabled(ctx, accountID, encrypted, false); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return TOTPEnrollmentStart{}, ErrUnauthorized
		}
		return TOTPEnrollmentStart{}, err
	}

	return TOTPEnrollmentStart{
		SecretBase32: security.EncodeTOTPSecretBase32(secret),
		ProvisioningURI: security.BuildTOTPProvisioningURI(
			secret,
			s.issuer,
			account.Login,
		),
	}, nil
}

// CompleteEnrollment finalises a pending enrollment by verifying the user
// can produce a current TOTP code from the secret stashed by
// StartEnrollment. On success: totp_enabled=true, the matching step is
// claimed so it cannot be reused, and every other session of the account
// is revoked (enabling 2FA is a security-state change).
func (s *TOTPService) CompleteEnrollment(
	ctx context.Context,
	accountID string,
	currentSessionTokenHash string,
	code string,
) error {
	if !s.Configured() {
		return ErrTOTPNotConfigured
	}

	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}
	if account.TOTPEnabled {
		return ErrTOTPAlreadyEnabled
	}
	if account.TOTPSecretEncrypted == "" {
		return ErrTOTPNotConfigured
	}

	rawSecret, err := security.DecryptField(
		account.TOTPSecretEncrypted,
		s.secretKey,
		aadForTOTPSecret(accountID),
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPSecretDecrypt, err)
	}

	step, ok := security.VerifyTOTPCode([]byte(rawSecret), code, s.now().UTC().Unix())
	if !ok {
		return ErrTOTPInvalidCode
	}

	claimed, err := s.store.ClaimTOTPStep(ctx, accountID, step)
	if err != nil {
		return err
	}
	if !claimed {
		return ErrTOTPReplayed
	}

	if err := s.store.UpdateTOTPSecretAndEnabled(
		ctx,
		accountID,
		account.TOTPSecretEncrypted,
		true,
	); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}

	// Enabling 2FA changes the account's security posture; invalidate other
	// sessions. The caller's session stays valid via currentSessionTokenHash.
	if err := s.store.DeleteSessionsForAccountExcept(ctx, accountID, currentSessionTokenHash); err != nil {
		return err
	}

	return nil
}

// Disable verifies the current password AND a current TOTP code, then
// clears the encrypted secret, resets last-used-step, and revokes every
// session of the account. Requiring the password on top of the TOTP code
// keeps a temporarily-borrowed authenticator from being able to remove 2FA
// on its own.
func (s *TOTPService) Disable(
	ctx context.Context,
	accountID string,
	currentPassword string,
	code string,
) error {
	if !s.Configured() {
		return ErrTOTPNotConfigured
	}

	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}
	if !account.TOTPEnabled {
		return ErrTOTPNotConfigured
	}

	if err := security.ComparePasswordHash(account.PasswordHash, currentPassword); err != nil {
		return ErrInvalidCurrentPassword
	}

	rawSecret, err := security.DecryptField(
		account.TOTPSecretEncrypted,
		s.secretKey,
		aadForTOTPSecret(accountID),
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTOTPSecretDecrypt, err)
	}

	step, ok := security.VerifyTOTPCode([]byte(rawSecret), code, s.now().UTC().Unix())
	if !ok {
		return ErrTOTPInvalidCode
	}

	claimed, err := s.store.ClaimTOTPStep(ctx, accountID, step)
	if err != nil {
		return err
	}
	if !claimed {
		return ErrTOTPReplayed
	}

	if err := s.store.UpdateTOTPSecretAndEnabled(ctx, accountID, "", false); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}

	if err := s.store.DeleteAllSessionsForAccount(ctx, accountID); err != nil {
		return err
	}

	// Any in-flight TOTP challenges for this account are now meaningless.
	if err := s.store.DeleteTOTPChallengesForAccount(ctx, accountID); err != nil {
		return err
	}

	return nil
}

// IssueChallenge mints a short-lived TOTP login challenge for an account
// that just passed password verification. The plaintext challenge id is
// returned to the caller; only the SHA-256 hash is persisted, so a leaked
// db row cannot be replayed without the issuer's response body.
func (s *TOTPService) IssueChallenge(
	ctx context.Context,
	accountID string,
) (challengeID string, expiresAt time.Time, err error) {
	plain, hash, tokenErr := security.NewOpaqueToken()
	if tokenErr != nil {
		return "", time.Time{}, tokenErr
	}

	now := s.now().UTC()
	expiresAt = now.Add(TOTPChallengeTTL)
	if storeErr := s.store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
		ChallengeIDHash: hash,
		AccountID:       accountID,
		CreatedAt:       now,
		ExpiresAt:       expiresAt,
	}); storeErr != nil {
		return "", time.Time{}, storeErr
	}

	return plain, expiresAt, nil
}

// VerifyChallenge consumes a TOTP login challenge and a code; on success it
// claims the matching TOTP step, deletes the challenge, and creates a fresh
// session for the account. Errors are deliberately specific enough to drive
// retry vs. restart UX (invalid_code is retryable in-place; challenge_invalid
// means the caller must start over).
func (s *TOTPService) VerifyChallenge(
	ctx context.Context,
	challengeID string,
	code string,
) (AuthResult, error) {
	if !s.Configured() {
		return AuthResult{}, ErrTOTPNotConfigured
	}

	challenge, err := s.store.FindTOTPChallengeByHash(ctx, security.HashToken(challengeID))
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return AuthResult{}, ErrTOTPChallengeInvalid
		}
		return AuthResult{}, err
	}

	now := s.now().UTC()
	if !challenge.ExpiresAt.After(now) {
		_ = s.store.DeleteTOTPChallengeByHash(ctx, security.HashToken(challengeID))
		return AuthResult{}, ErrTOTPChallengeInvalid
	}

	account, err := s.store.FindAccountByID(ctx, challenge.AccountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return AuthResult{}, ErrTOTPChallengeInvalid
		}
		return AuthResult{}, err
	}
	if !account.TOTPEnabled || account.TOTPSecretEncrypted == "" {
		// Challenge stale: 2FA was disabled between Login and this call.
		_ = s.store.DeleteTOTPChallengeByHash(ctx, security.HashToken(challengeID))
		return AuthResult{}, ErrTOTPChallengeInvalid
	}

	rawSecret, err := security.DecryptField(
		account.TOTPSecretEncrypted,
		s.secretKey,
		aadForTOTPSecret(account.ID),
	)
	if err != nil {
		return AuthResult{}, fmt.Errorf("%w: %v", ErrTOTPSecretDecrypt, err)
	}

	step, ok := security.VerifyTOTPCode([]byte(rawSecret), code, now.Unix())
	if !ok {
		return AuthResult{}, ErrTOTPInvalidCode
	}

	claimed, err := s.store.ClaimTOTPStep(ctx, account.ID, step)
	if err != nil {
		return AuthResult{}, err
	}
	if !claimed {
		return AuthResult{}, ErrTOTPReplayed
	}

	if err := s.store.DeleteTOTPChallengeByHash(ctx, security.HashToken(challengeID)); err != nil {
		return AuthResult{}, err
	}

	return s.auth.CreateSessionForAccount(ctx, account.ID)
}

// aadForTOTPSecret returns the AEAD aad that binds an encrypted TOTP secret
// to a single account row. Including the account id prevents a swap of one
// account's ciphertext into another row from being accepted by DecryptField.
func aadForTOTPSecret(accountID string) []byte {
	return []byte("ovumcy.sync-community.field.totp_secret:" + accountID)
}
