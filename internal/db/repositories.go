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
		`INSERT INTO accounts (id, login, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		account.ID,
		account.Login,
		account.PasswordHash,
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

func (s *Store) FindAccountByLogin(ctx context.Context, login string) (models.Account, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, login, password_hash, created_at FROM accounts WHERE login = ?`,
		login,
	)

	return scanAccount(row)
}

func (s *Store) FindAccountByID(ctx context.Context, accountID string) (models.Account, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, login, password_hash, created_at FROM accounts WHERE id = ?`,
		accountID,
	)

	return scanAccount(row)
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

func scanAccount(row interface{ Scan(dest ...any) error }) (models.Account, error) {
	var account models.Account
	var createdAt string
	if err := row.Scan(&account.ID, &account.Login, &account.PasswordHash, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Account{}, ErrNotFound
		}
		return models.Account{}, fmt.Errorf("scan account: %w", err)
	}
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
