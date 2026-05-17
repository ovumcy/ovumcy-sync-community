package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

var ErrNotFound = errors.New("not_found")
var ErrConflict = errors.New("conflict")

func (s *Store) CreateAccount(ctx context.Context, account models.Account) (models.Account, error) {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO accounts (id, login, password_hash, recovery_code_hash, mode, premium_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		account.ID,
		account.Login,
		account.PasswordHash,
		account.RecoveryCodeHash,
		account.Mode,
		boolToInt(account.PremiumActive),
		account.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return models.Account{}, ErrConflict
		}
		return models.Account{}, fmt.Errorf("insert account: %w", err)
	}

	return account, nil
}

func (s *Store) UpsertManagedAccount(ctx context.Context, account models.Account) (models.Account, error) {
	_, err := s.db.ExecContext(
		ctx,
		`
INSERT INTO accounts (id, login, password_hash, recovery_code_hash, mode, premium_active, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  login = excluded.login,
  password_hash = excluded.password_hash,
  mode = excluded.mode,
  premium_active = excluded.premium_active
`,
		account.ID,
		account.Login,
		account.PasswordHash,
		account.RecoveryCodeHash,
		account.Mode,
		boolToInt(account.PremiumActive),
		account.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return models.Account{}, ErrConflict
		}
		return models.Account{}, fmt.Errorf("upsert managed account: %w", err)
	}

	return account, nil
}

func (s *Store) FindAccountByLogin(ctx context.Context, login string) (models.Account, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, login, password_hash, recovery_code_hash, mode, premium_active, created_at, totp_secret_encrypted, totp_enabled, totp_last_used_step FROM accounts WHERE login = ?`,
		login,
	)

	return scanAccount(row)
}

func (s *Store) FindAccountByID(ctx context.Context, accountID string) (models.Account, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, login, password_hash, recovery_code_hash, mode, premium_active, created_at, totp_secret_encrypted, totp_enabled, totp_last_used_step FROM accounts WHERE id = ?`,
		accountID,
	)

	return scanAccount(row)
}

func (s *Store) UpdateAccountPasswordHash(ctx context.Context, accountID string, passwordHash string) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET password_hash = ? WHERE id = ?`,
		passwordHash,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("update account password: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update account password rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *Store) UpdateAccountPasswordAndRecoveryHash(
	ctx context.Context,
	accountID string,
	passwordHash string,
	recoveryCodeHash string,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET password_hash = ?, recovery_code_hash = ? WHERE id = ?`,
		passwordHash,
		recoveryCodeHash,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("update account password and recovery: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update account password and recovery rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *Store) UpdateAccountRecoveryCodeHash(
	ctx context.Context,
	accountID string,
	recoveryCodeHash string,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET recovery_code_hash = ? WHERE id = ?`,
		recoveryCodeHash,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("update account recovery code: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update account recovery code rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *Store) CreateSession(ctx context.Context, session models.Session) (models.Session, error) {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO sessions (id, account_id, token_hash, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.AccountID,
		session.TokenHash,
		session.CreatedAt.UTC().Format(time.RFC3339Nano),
		session.LastSeenAt.UTC().Format(time.RFC3339Nano),
		session.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return models.Session{}, fmt.Errorf("insert session: %w", err)
	}

	return session, nil
}

func (s *Store) FindSessionByTokenHash(ctx context.Context, tokenHash string) (models.Session, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, account_id, token_hash, created_at, last_seen_at, expires_at FROM sessions WHERE token_hash = ?`,
		tokenHash,
	)

	return scanSession(row)
}

func (s *Store) TouchSession(ctx context.Context, sessionID string, lastSeenAt time.Time) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`,
		lastSeenAt.UTC().Format(time.RFC3339Nano),
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("touch session rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateTOTPSecretAndEnabled writes the new TOTP secret ciphertext alongside
// the totp_enabled flag in one statement. Called when enrolling (set secret +
// enable) and when disabling (clear secret + disable). totp_last_used_step
// is reset on every transition so a previously consumed step does not block
// a fresh enrollment.
func (s *Store) UpdateTOTPSecretAndEnabled(
	ctx context.Context,
	accountID string,
	encryptedSecret string,
	enabled bool,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET totp_secret_encrypted = ?, totp_enabled = ?, totp_last_used_step = 0 WHERE id = ?`,
		encryptedSecret,
		boolToInt(enabled),
		accountID,
	)
	if err != nil {
		return fmt.Errorf("update totp secret: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update totp secret rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

// ClaimTOTPStep atomically advances totp_last_used_step to step iff it is
// strictly greater than the persisted value. Returns true when the row was
// updated (the step is now consumed by this caller) and false when the step
// was already at or beyond `step` — a replay or concurrent loser.
func (s *Store) ClaimTOTPStep(
	ctx context.Context,
	accountID string,
	step int64,
) (bool, error) {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET totp_last_used_step = ? WHERE id = ? AND totp_last_used_step < ?`,
		step,
		accountID,
		step,
	)
	if err != nil {
		return false, fmt.Errorf("claim totp step: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("claim totp step rows: %w", err)
	}
	return affected == 1, nil
}

func (s *Store) UpsertTOTPChallenge(
	ctx context.Context,
	challenge models.TOTPChallenge,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`
INSERT INTO totp_challenges (challenge_id_hash, account_id, created_at, expires_at)
VALUES (?, ?, ?, ?)
`,
		challenge.ChallengeIDHash,
		challenge.AccountID,
		challenge.CreatedAt.UTC().Format(time.RFC3339Nano),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert totp challenge: %w", err)
	}

	return nil
}

func (s *Store) FindTOTPChallengeByHash(
	ctx context.Context,
	challengeIDHash string,
) (models.TOTPChallenge, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT challenge_id_hash, account_id, created_at, expires_at FROM totp_challenges WHERE challenge_id_hash = ?`,
		challengeIDHash,
	)

	var challenge models.TOTPChallenge
	var createdAt string
	var expiresAt string
	if err := row.Scan(
		&challenge.ChallengeIDHash,
		&challenge.AccountID,
		&createdAt,
		&expiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.TOTPChallenge{}, ErrNotFound
		}
		return models.TOTPChallenge{}, fmt.Errorf("scan totp challenge: %w", err)
	}
	challenge.CreatedAt = mustParseTime(createdAt)
	challenge.ExpiresAt = mustParseTime(expiresAt)
	return challenge, nil
}

// IncrementTOTPChallengeFailedAttempts atomically increments the per-row
// counter and returns the new value. Used by VerifyChallenge to enforce a
// finite number of guesses per challenge id so an attacker cannot brute-force
// the 6-digit code through the challenge's 5-minute lifetime.
//
// Returns ErrNotFound when the challenge no longer exists (e.g. already
// consumed or expired).
func (s *Store) IncrementTOTPChallengeFailedAttempts(
	ctx context.Context,
	challengeIDHash string,
) (int, error) {
	row := s.db.QueryRowContext(
		ctx,
		`UPDATE totp_challenges SET failed_attempts = failed_attempts + 1 WHERE challenge_id_hash = ? RETURNING failed_attempts`,
		challengeIDHash,
	)

	var failedAttempts int
	if err := row.Scan(&failedAttempts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("increment totp challenge attempts: %w", err)
	}
	return failedAttempts, nil
}

func (s *Store) DeleteTOTPChallengeByHash(
	ctx context.Context,
	challengeIDHash string,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM totp_challenges WHERE challenge_id_hash = ?`,
		challengeIDHash,
	)
	if err != nil {
		return fmt.Errorf("delete totp challenge: %w", err)
	}
	return nil
}

func (s *Store) DeleteTOTPChallengesForAccount(
	ctx context.Context,
	accountID string,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM totp_challenges WHERE account_id = ?`,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("delete totp challenges for account: %w", err)
	}
	return nil
}

func (s *Store) UpsertPasswordResetToken(
	ctx context.Context,
	resetToken models.PasswordResetToken,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`
INSERT INTO password_reset_tokens (account_id, token_hash, created_at, expires_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(account_id) DO UPDATE SET
  token_hash = excluded.token_hash,
  created_at = excluded.created_at,
  expires_at = excluded.expires_at
`,
		resetToken.AccountID,
		resetToken.TokenHash,
		resetToken.CreatedAt.UTC().Format(time.RFC3339Nano),
		resetToken.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("upsert password reset token: %w", err)
	}

	return nil
}

func (s *Store) FindPasswordResetTokenByHash(
	ctx context.Context,
	tokenHash string,
) (models.PasswordResetToken, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT account_id, token_hash, created_at, expires_at FROM password_reset_tokens WHERE token_hash = ?`,
		tokenHash,
	)

	var resetToken models.PasswordResetToken
	var createdAt string
	var expiresAt string
	if err := row.Scan(
		&resetToken.AccountID,
		&resetToken.TokenHash,
		&createdAt,
		&expiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.PasswordResetToken{}, ErrNotFound
		}
		return models.PasswordResetToken{}, fmt.Errorf("scan password reset token: %w", err)
	}
	resetToken.CreatedAt = mustParseTime(createdAt)
	resetToken.ExpiresAt = mustParseTime(expiresAt)
	return resetToken, nil
}

func (s *Store) DeletePasswordResetTokensForAccount(
	ctx context.Context,
	accountID string,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM password_reset_tokens WHERE account_id = ?`,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("delete password reset tokens: %w", err)
	}

	return nil
}

func (s *Store) DeleteSessionsForAccountExcept(ctx context.Context, accountID string, keepTokenHash string) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM sessions WHERE account_id = ? AND token_hash != ?`,
		accountID,
		keepTokenHash,
	)
	if err != nil {
		return fmt.Errorf("delete other sessions: %w", err)
	}

	return nil
}

func (s *Store) DeleteAllSessionsForAccount(ctx context.Context, accountID string) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM sessions WHERE account_id = ?`,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("delete all sessions: %w", err)
	}

	return nil
}

func (s *Store) DeleteSessionByTokenHash(ctx context.Context, tokenHash string) error {
	result, err := s.db.ExecContext(
		ctx,
		`DELETE FROM sessions WHERE token_hash = ?`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete session rows: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *Store) CountDevicesForAccount(ctx context.Context, accountID string) (int, error) {
	var count int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(1) FROM devices WHERE account_id = ?`,
		accountID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count devices: %w", err)
	}

	return count, nil
}

func (s *Store) FindDevice(ctx context.Context, accountID string, deviceID string) (models.Device, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT device_id, account_id, device_label, created_at, last_seen_at FROM devices WHERE account_id = ? AND device_id = ?`,
		accountID,
		deviceID,
	)

	return scanDevice(row)
}

func (s *Store) UpsertDevice(ctx context.Context, device models.Device) (models.Device, error) {
	_, err := s.db.ExecContext(
		ctx,
		`
INSERT INTO devices (device_id, account_id, device_label, created_at, last_seen_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(account_id, device_id) DO UPDATE SET
  device_label = excluded.device_label,
  last_seen_at = excluded.last_seen_at
`,
		device.DeviceID,
		device.AccountID,
		device.DeviceLabel,
		device.CreatedAt.UTC().Format(time.RFC3339Nano),
		device.LastSeenAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return models.Device{}, fmt.Errorf("upsert device: %w", err)
	}

	return device, nil
}

func (s *Store) GetEncryptedBlob(ctx context.Context, accountID string) (models.EncryptedBlob, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT account_id, schema_version, generation, checksum_sha256, ciphertext, ciphertext_size, updated_at FROM encrypted_blobs WHERE account_id = ?`,
		accountID,
	)

	return scanBlob(row)
}

func (s *Store) UpsertEncryptedBlob(ctx context.Context, blob models.EncryptedBlob) (models.EncryptedBlob, error) {
	_, err := s.db.ExecContext(
		ctx,
		`
INSERT INTO encrypted_blobs (account_id, schema_version, generation, checksum_sha256, ciphertext, ciphertext_size, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
ON CONFLICT(account_id) DO UPDATE SET
  schema_version = excluded.schema_version,
  generation = excluded.generation,
  checksum_sha256 = excluded.checksum_sha256,
  ciphertext = excluded.ciphertext,
  ciphertext_size = excluded.ciphertext_size,
  updated_at = excluded.updated_at
`,
		blob.AccountID,
		blob.SchemaVersion,
		blob.Generation,
		blob.ChecksumSHA256,
		blob.Ciphertext,
		blob.CiphertextSize,
		blob.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return models.EncryptedBlob{}, fmt.Errorf("upsert blob: %w", err)
	}

	return blob, nil
}

func (s *Store) GetRecoveryKeyPackage(
	ctx context.Context,
	accountID string,
) (models.RecoveryKeyPackage, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT account_id, algorithm, kdf, mnemonic_word_count, wrap_nonce_hex, wrapped_master_key_hex, phrase_fingerprint_hex, updated_at
		 FROM recovery_key_packages
		 WHERE account_id = ?`,
		accountID,
	)

	return scanRecoveryKeyPackage(row)
}

func (s *Store) UpsertRecoveryKeyPackage(
	ctx context.Context,
	recoveryKeyPackage models.RecoveryKeyPackage,
) (models.RecoveryKeyPackage, error) {
	_, err := s.db.ExecContext(
		ctx,
		`
INSERT INTO recovery_key_packages (
  account_id,
  algorithm,
  kdf,
  mnemonic_word_count,
  wrap_nonce_hex,
  wrapped_master_key_hex,
  phrase_fingerprint_hex,
  updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(account_id) DO UPDATE SET
  algorithm = excluded.algorithm,
  kdf = excluded.kdf,
  mnemonic_word_count = excluded.mnemonic_word_count,
  wrap_nonce_hex = excluded.wrap_nonce_hex,
  wrapped_master_key_hex = excluded.wrapped_master_key_hex,
  phrase_fingerprint_hex = excluded.phrase_fingerprint_hex,
  updated_at = excluded.updated_at
`,
		recoveryKeyPackage.AccountID,
		recoveryKeyPackage.Algorithm,
		recoveryKeyPackage.KDF,
		recoveryKeyPackage.MnemonicWordCount,
		recoveryKeyPackage.WrapNonceHex,
		recoveryKeyPackage.WrappedMasterKeyHex,
		recoveryKeyPackage.PhraseFingerprintHex,
		recoveryKeyPackage.UpdatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return models.RecoveryKeyPackage{}, fmt.Errorf("upsert recovery key package: %w", err)
	}

	return recoveryKeyPackage, nil
}

func scanAccount(row interface{ Scan(dest ...any) error }) (models.Account, error) {
	var account models.Account
	var createdAt string
	var premiumActive int
	var totpEnabled int
	if err := row.Scan(
		&account.ID,
		&account.Login,
		&account.PasswordHash,
		&account.RecoveryCodeHash,
		&account.Mode,
		&premiumActive,
		&createdAt,
		&account.TOTPSecretEncrypted,
		&totpEnabled,
		&account.TOTPLastUsedStep,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Account{}, ErrNotFound
		}
		return models.Account{}, fmt.Errorf("scan account: %w", err)
	}
	account.PremiumActive = premiumActive != 0
	account.TOTPEnabled = totpEnabled != 0
	account.CreatedAt = mustParseTime(createdAt)
	return account, nil
}

func scanSession(row interface{ Scan(dest ...any) error }) (models.Session, error) {
	var session models.Session
	var createdAt string
	var lastSeenAt string
	var expiresAt string
	if err := row.Scan(
		&session.ID,
		&session.AccountID,
		&session.TokenHash,
		&createdAt,
		&lastSeenAt,
		&expiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Session{}, ErrNotFound
		}
		return models.Session{}, fmt.Errorf("scan session: %w", err)
	}
	session.CreatedAt = mustParseTime(createdAt)
	session.LastSeenAt = mustParseTime(lastSeenAt)
	session.ExpiresAt = mustParseTime(expiresAt)
	return session, nil
}

func scanDevice(row interface{ Scan(dest ...any) error }) (models.Device, error) {
	var device models.Device
	var createdAt string
	var lastSeenAt string
	if err := row.Scan(
		&device.DeviceID,
		&device.AccountID,
		&device.DeviceLabel,
		&createdAt,
		&lastSeenAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Device{}, ErrNotFound
		}
		return models.Device{}, fmt.Errorf("scan device: %w", err)
	}
	device.CreatedAt = mustParseTime(createdAt)
	device.LastSeenAt = mustParseTime(lastSeenAt)
	return device, nil
}

func scanBlob(row interface{ Scan(dest ...any) error }) (models.EncryptedBlob, error) {
	var blob models.EncryptedBlob
	var updatedAt string
	if err := row.Scan(
		&blob.AccountID,
		&blob.SchemaVersion,
		&blob.Generation,
		&blob.ChecksumSHA256,
		&blob.Ciphertext,
		&blob.CiphertextSize,
		&updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.EncryptedBlob{}, ErrNotFound
		}
		return models.EncryptedBlob{}, fmt.Errorf("scan blob: %w", err)
	}
	blob.UpdatedAt = mustParseTime(updatedAt)
	return blob, nil
}

func scanRecoveryKeyPackage(
	row interface{ Scan(dest ...any) error },
) (models.RecoveryKeyPackage, error) {
	var recoveryKeyPackage models.RecoveryKeyPackage
	var updatedAt string
	if err := row.Scan(
		&recoveryKeyPackage.AccountID,
		&recoveryKeyPackage.Algorithm,
		&recoveryKeyPackage.KDF,
		&recoveryKeyPackage.MnemonicWordCount,
		&recoveryKeyPackage.WrapNonceHex,
		&recoveryKeyPackage.WrappedMasterKeyHex,
		&recoveryKeyPackage.PhraseFingerprintHex,
		&updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.RecoveryKeyPackage{}, ErrNotFound
		}
		return models.RecoveryKeyPackage{}, fmt.Errorf("scan recovery key package: %w", err)
	}
	recoveryKeyPackage.UpdatedAt = mustParseTime(updatedAt)
	return recoveryKeyPackage, nil
}

func mustParseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed
	}

	parsed, err = time.Parse("2006-01-02 15:04:05", value)
	if err == nil {
		return parsed.UTC()
	}

	panic(fmt.Sprintf("parse stored timestamp %q: %v", value, err))
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
