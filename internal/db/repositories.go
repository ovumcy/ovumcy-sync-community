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

// ErrStaleGeneration is returned by UpsertEncryptedBlob when the incoming
// generation is not strictly greater than the persisted generation. The CAS
// lives in the SQL statement; service code must surface this to the API as
// the public stale-generation error and never pre-check via GetEncryptedBlob
// (TOCTOU).
var ErrStaleGeneration = errors.New("stale_generation")

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

// UpsertManagedAccount provisions or refreshes a mode=managed account. Every
// call — including a plain session-mint refresh, not just first provisioning
// — clears lapsed_at unconditionally: this is the "mint clears the marker"
// half of the entitlement-lapse cleanup contract (see SetAccountLapsed and
// LapsedAccountSweepService), so an account that resubscribes and mints a
// new session is immediately safe from the purge sweep again, without
// needing a separate call. The INSERT branch never needs to set lapsed_at
// explicitly: the column defaults to NULL for a brand-new row.
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
  premium_active = excluded.premium_active,
  lapsed_at = NULL
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
		return fmt.Errorf("update account password rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
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
		return fmt.Errorf("update account password and recovery rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
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
		return fmt.Errorf("update account recovery code rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteAccount erases every row this server holds for accountID: the
// account row itself plus every child row keyed by account_id (sessions,
// devices, the encrypted sync blob, the wrapped recovery-key package,
// pending password reset tokens, and TOTP login challenges).
//
// All deletes run inside one transaction so a failure partway through never
// leaves a partially-erased account: either every row is gone or none are.
// `accounts.id` cascades (ON DELETE CASCADE) to every one of those tables
// already, so the child deletes here are defense-in-depth against future
// schema drift rather than the only thing standing between us and orphaned
// rows — the explicit statements keep the erased-rows contract legible and
// independently verifiable without relying on cascade behavior alone.
//
// Returns ErrNotFound when the account no longer exists (RowsAffected == 0
// on the `accounts` delete), which the caller uses to make deletion
// idempotent: a repeat call after a successful delete is a no-op, not an
// error.
func (s *Store) DeleteAccount(ctx context.Context, accountID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete account: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	childTables := []string{
		"sessions",
		"devices",
		"encrypted_blobs",
		"recovery_key_packages",
		"password_reset_tokens",
		"totp_challenges",
	}
	for _, table := range childTables {
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM `+table+` WHERE account_id = ?`, // #nosec G202 -- table ranges only over the fixed childTables allowlist above, never user input; account_id is bound as a placeholder
			accountID,
		); err != nil {
			return fmt.Errorf("delete account %s rows: %w", table, err)
		}
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, accountID)
	if err != nil {
		return fmt.Errorf("delete account row: %w", err) // codecov:ignore -- isolating this specific step needs "accounts" to exist for all 6 child-table deletes above to succeed, then vanish only for this one; dropping "accounts" wholesale instead fails the very first child delete (confirmed empirically: with foreign_keys=ON, SQLite rejects DML against a child table whose FK-referenced table is gone, even though the statement never touches the FK column), same as TestDeleteAccountReturnsErrorAndRollsBackWhenAChildTableIsDropped. Needs a fake driver.
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete account row rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete account: %w", err) // codecov:ignore -- on this store's single-connection sqlite (WAL, busy_timeout) a COMMIT whose statements all succeeded has no deterministically injectable in-process failure; needs a fake driver, the same deviation documented for DeleteLapsedManagedAccount's commit branch below.
	}

	return nil
}

// DefaultLapsedAccountSweepLimit bounds how many candidate lapsed accounts
// ListLapsedManagedAccountIDs returns when the caller (the
// purge-lapsed-accounts CLI subcommand) does not request an explicit -limit.
// Mirrors the intent of ovumcy-managed's ListGuestAccountIDs default: an
// operator invocation with no flags must never attempt to load an unbounded
// candidate set in one call.
const DefaultLapsedAccountSweepLimit = 500

// SetAccountLapsed records accountID's entitlement lapse for the purge sweep
// (LapsedAccountSweepService): premium_active is cleared and lapsed_at is set
// to lapsedAt UNLESS a lapse is already recorded, in which case the
// already-stored lapsed_at is preserved (the COALESCE) rather than
// overwritten. This is what makes a replayed lapse signal idempotent without
// weakening the grace-period contract: repeating the signal can never push
// the sweep's grace deadline further out, only a session mint
// (UpsertManagedAccount) or an explicit active=true retraction
// (ClearAccountLapse) resets the marker.
//
// Scoped to mode = 'managed' so the bridge credential can never mark a
// self-hosted account lapsed even if the id collides — the same defense
// PurgeManagedAccount already applies to deletion. Returns ErrNotFound when
// accountID does not exist or is not a managed account (RowsAffected == 0);
// callers use this the same way DeleteAccount's callers use ErrNotFound, to
// make the write idempotent for an account this server has never heard of.
func (s *Store) SetAccountLapsed(ctx context.Context, accountID string, lapsedAt time.Time) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET premium_active = 0, lapsed_at = COALESCE(lapsed_at, ?) WHERE id = ? AND mode = 'managed'`,
		lapsedAt.UTC().Format(time.RFC3339Nano),
		accountID,
	)
	if err != nil {
		return fmt.Errorf("set account lapsed: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("set account lapsed rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

// ClearAccountLapse retracts a previously recorded lapse marker WITHOUT
// touching premium_active — turning premium back on and issuing a session
// both remain the mint path's job (UpsertManagedAccount, called from
// CreateManagedSession), which already clears lapsed_at on every successful
// mint. This method backs the explicit active=true retraction path
// (ManagedBridgeService.SetAccountLapseSignal): a managed-side false
// positive corrected before the account's next session mint. Scoped to
// mode = 'managed' for the same reason as SetAccountLapsed. Clearing an
// already-clear marker is a no-op success. Returns ErrNotFound when
// accountID does not exist or is not a managed account.
func (s *Store) ClearAccountLapse(ctx context.Context, accountID string) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET lapsed_at = NULL WHERE id = ? AND mode = 'managed'`,
		accountID,
	)
	if err != nil {
		return fmt.Errorf("clear account lapse: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("clear account lapse rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

// GetAccountLapsedAt returns accountID's current lapsed_at marker, or nil
// when the account is not lapsed. There is no corresponding field on
// models.Account — lapsed_at is written and read only by the narrow
// lapse-cleanup call paths above and by tests asserting their contract,
// mirroring how password_reset_tokens.consumed_at has no Go struct field
// either. Returns ErrNotFound when accountID does not exist.
func (s *Store) GetAccountLapsedAt(ctx context.Context, accountID string) (*time.Time, error) {
	var lapsedAt sql.NullString
	err := s.db.QueryRowContext(
		ctx,
		`SELECT lapsed_at FROM accounts WHERE id = ?`,
		accountID,
	).Scan(&lapsedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get account lapsed_at: %w", err)
	}
	if !lapsedAt.Valid {
		return nil, nil
	}

	parsed := mustParseTime(lapsedAt.String)
	return &parsed, nil
}

// ListLapsedManagedAccountIDs returns up to limit managed account ids whose
// lapsed_at marker is set and strictly older than cutoff (lapsed_at <
// cutoff), oldest lapse first. A non-positive limit falls back to
// DefaultLapsedAccountSweepLimit. mode = 'managed' is an explicit
// defense-in-depth filter, not the only thing keeping self-hosted accounts
// out of this list — SetAccountLapsed's own WHERE clause means a
// self-hosted account's lapsed_at can never be non-NULL in the first place.
func (s *Store) ListLapsedManagedAccountIDs(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		limit = DefaultLapsedAccountSweepLimit
	}

	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id FROM accounts WHERE mode = 'managed' AND lapsed_at IS NOT NULL AND lapsed_at < ? ORDER BY lapsed_at LIMIT ?`,
		cutoff.UTC().Format(time.RFC3339Nano),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list lapsed managed account ids: %w", err)
	}
	defer func() { _ = rows.Close() }()

	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan lapsed managed account id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list lapsed managed account ids rows: %w", err) // codecov:ignore -- a mid-iteration step failure is not deterministically injectable in-process: a dropped table or pre-canceled context fails QueryContext first (covered), and row-shape corruption surfaces at rows.Scan (covered); needs a fake driver.
	}

	return ids, nil
}

// DeleteLapsedManagedAccount erases accountID exactly like DeleteAccount —
// every row this server holds for it, in one transaction — but ONLY when it
// is still a managed account whose lapsed_at marker is set and strictly
// older than cutoff at the moment the transaction runs. This is the
// delete-time entitlement re-check the lapse-cleanup design requires: a
// session mint between the sweep's candidate listing (
// ListLapsedManagedAccountIDs) and this call clears lapsed_at
// (UpsertManagedAccount), which makes the final conditional DELETE affect
// zero rows, so the whole transaction rolls back — including the
// unconditional child-table deletes above, which then never reach disk — and
// the account (and its data) survives completely intact.
//
// Returns ErrNotFound both when the account no longer exists AND when it no
// longer qualifies (self-hosted, un-lapsed, or lapsed less than cutoff ago)
// — deliberately indistinguishable, since the caller's response to either is
// identical: skip it, it is not eligible for deletion right now.
func (s *Store) DeleteLapsedManagedAccount(ctx context.Context, accountID string, cutoff time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete lapsed account: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Deliberate inline copy of DeleteAccount's child-table loop (same
	// tables, same order, same #nosec rationale) rather than a shared
	// helper, so the long-stable DeleteAccount above stays byte-identical
	// and this function's erasure contract is self-contained. Keep the two
	// lists in sync; each side's erases-every-row test pins its copy
	// (TestDeleteAccountErasesEveryChildRowAndIsIdempotent there, the
	// repository and sweep lapse tests here).
	childTables := []string{
		"sessions",
		"devices",
		"encrypted_blobs",
		"recovery_key_packages",
		"password_reset_tokens",
		"totp_challenges",
	}
	for _, table := range childTables {
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM `+table+` WHERE account_id = ?`, // #nosec G202 -- table ranges only over the fixed childTables allowlist above, never user input; account_id is bound as a placeholder
			accountID,
		); err != nil {
			return fmt.Errorf("delete account %s rows: %w", table, err)
		}
	}

	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM accounts WHERE id = ? AND mode = 'managed' AND lapsed_at IS NOT NULL AND lapsed_at < ?`,
		accountID,
		cutoff.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("delete lapsed account row: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete lapsed account row rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete lapsed account: %w", err) // codecov:ignore -- on this store's single-connection sqlite (WAL, busy_timeout) a COMMIT whose statements all succeeded has no deterministically injectable in-process failure; needs a fake driver.
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
		return fmt.Errorf("touch session rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateTOTPSecretAndEnabled writes the TOTP secret ciphertext alongside the
// totp_enabled flag in one statement, resetting totp_last_used_step to 0. It
// is the secret-write transition: storing a fresh pending secret at enrollment
// start (enabled=false) and clearing the secret on disable / recovery reset
// (empty ciphertext, enabled=false). Resetting the step here is deliberate and
// safe — either the secret is brand new (any leftover step from a prior secret
// must not reject the new secret's first verify) or the secret is gone (no
// code can verify against it). The enable transition does NOT go through here;
// it uses SetTOTPEnabled, which preserves the step claimed by the verifying
// code so that same code cannot be replayed inside its skew window.
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
		return fmt.Errorf("update totp secret rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

// SetTOTPEnabled flips only the totp_enabled flag, leaving both
// totp_secret_encrypted and totp_last_used_step untouched. It is the enable
// transition at the end of CompleteEnrollment: the verifying code has already
// been consumed via ClaimTOTPStep, so the claimed step MUST survive this write
// or the just-used enrollment code would be replayable against the login
// challenge and disable paths within its ±1-step skew window (RFC 6238 §5.2).
// Keeping the secret column out of the statement also avoids a redundant
// re-write of the ciphertext the caller already holds.
func (s *Store) SetTOTPEnabled(
	ctx context.Context,
	accountID string,
	enabled bool,
) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE accounts SET totp_enabled = ? WHERE id = ?`,
		boolToInt(enabled),
		accountID,
	)
	if err != nil {
		return fmt.Errorf("set totp enabled: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("set totp enabled rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
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
		return false, fmt.Errorf("claim totp step rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
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
INSERT INTO password_reset_tokens (account_id, token_hash, created_at, expires_at, consumed_at)
VALUES (?, ?, ?, ?, NULL)
ON CONFLICT(account_id) DO UPDATE SET
  token_hash = excluded.token_hash,
  created_at = excluded.created_at,
  expires_at = excluded.expires_at,
  consumed_at = NULL
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

// ConsumePasswordResetToken atomically claims the matching token via a single
// UPDATE ... WHERE consumed_at IS NULL AND expires_at > now CAS. Returns the
// claimed row only when RowsAffected == 1; ErrNotFound otherwise (unknown
// token, already consumed, or expired). This is the single source of truth
// for "is this reset token still actionable" — callers must not pre-check
// expiry or pre-load the token, or the race the CAS prevents reopens.
func (s *Store) ConsumePasswordResetToken(
	ctx context.Context,
	tokenHash string,
	now time.Time,
) (models.PasswordResetToken, error) {
	nowFormatted := now.UTC().Format(time.RFC3339Nano)
	row := s.db.QueryRowContext(
		ctx,
		`UPDATE password_reset_tokens
		 SET consumed_at = ?
		 WHERE token_hash = ?
		   AND consumed_at IS NULL
		   AND expires_at > ?
		 RETURNING account_id, token_hash, created_at, expires_at`,
		nowFormatted,
		tokenHash,
		nowFormatted,
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
		return fmt.Errorf("delete session rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
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

// ListDevicesForAccount returns every device attached to the account, oldest
// first. The query is account-scoped so one account can never enumerate
// another's devices.
func (s *Store) ListDevicesForAccount(ctx context.Context, accountID string) ([]models.Device, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT device_id, account_id, device_label, created_at, last_seen_at FROM devices WHERE account_id = ? ORDER BY created_at`,
		accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer func() { _ = rows.Close() }()

	devices := make([]models.Device, 0)
	for rows.Next() {
		device, scanErr := scanDevice(rows)
		if scanErr != nil {
			return nil, scanErr // codecov:ignore -- every scanDevice destination is a plain string and SQLite's TEXT-affinity columns coerce any stored value (including BLOB) to string without a scan error, the same limitation TestScanAccountReturnsGenericErrorOnTypeMismatch documents for scanSession; not reachable via SQL-DML alone, needs a fake driver.
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list devices rows: %w", err) // codecov:ignore -- a mid-iteration step failure is not deterministically injectable in-process: a dropped table fails QueryContext first (covered), and row-shape corruption surfaces at rows.Scan (see scanErr above); needs a fake driver, the same deviation documented for ListLapsedManagedAccountIDs' rows.Err() branch.
	}

	return devices, nil
}

// DeleteDevice removes one device from the account. The DELETE is scoped by
// both account_id and device_id, so a caller can only ever delete its own
// devices (no IDOR). Returns ErrNotFound when the account has no such device.
func (s *Store) DeleteDevice(ctx context.Context, accountID string, deviceID string) error {
	result, err := s.db.ExecContext(
		ctx,
		`DELETE FROM devices WHERE account_id = ? AND device_id = ?`,
		accountID,
		deviceID,
	)
	if err != nil {
		return fmt.Errorf("delete device: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete device rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); needs a fake driver, the same deviation documented for UpsertEncryptedBlob's RowsAffected branch in fault_injection_test.go.
	}
	if affected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *Store) GetEncryptedBlob(ctx context.Context, accountID string) (models.EncryptedBlob, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT account_id, schema_version, generation, checksum_sha256, ciphertext, ciphertext_size, updated_at FROM encrypted_blobs WHERE account_id = ?`,
		accountID,
	)

	return scanBlob(row)
}

// UpsertEncryptedBlob inserts a new blob row or atomically advances an existing
// one when the incoming generation strictly exceeds the persisted generation.
// The "if newer" CAS lives in the WHERE clause of the ON CONFLICT DO UPDATE
// branch so that a concurrent loser (older or equal generation reaching the
// statement after a higher generation has already committed) is rejected as
// ErrStaleGeneration instead of overwriting fresher data. Callers must not
// pre-load existingBlob.Generation and compare in service code — the TOCTOU
// window between read and write reopens the race the CAS prevents.
//
// Returns ErrStaleGeneration when an existing row already has
// generation >= blob.Generation (RowsAffected == 0 on the conflict-update
// branch); the caller should map this to its public stale-generation error.
func (s *Store) UpsertEncryptedBlob(ctx context.Context, blob models.EncryptedBlob) (models.EncryptedBlob, error) {
	result, err := s.db.ExecContext(
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
WHERE excluded.generation > encrypted_blobs.generation
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

	affected, err := result.RowsAffected()
	if err != nil {
		return models.EncryptedBlob{}, fmt.Errorf("upsert blob rows: %w", err) // codecov:ignore -- modernc sqlite's Result.RowsAffected cannot fail once Exec succeeded (value captured at exec time); not reachable via the table-drop technique (ExecContext itself fails first, before RowsAffected is ever called) — see TestBlobAndRecoveryUpsertsReturnErrorWhenTablesAreDropped in fault_injection_test.go. Needs a fake driver.
	}
	if affected == 0 {
		return models.EncryptedBlob{}, ErrStaleGeneration
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
