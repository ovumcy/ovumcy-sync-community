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
		return AuthResult{}, err // codecov:ignore -- UpsertManagedAccount's generic ExecContext-error branch needs the accounts table gone or otherwise faulted, but the FindAccountByID lookup just above already touches accounts as this function's first store call, so isolating a second, later accounts-table failure needs a fake driver (same same-table-multi-step limitation as the RowsAffected/COMMIT deviations in internal/db/fault_injection_test.go).
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
			return nil // codecov:ignore -- TOCTOU race: account deleted between the lookup above and this delete; an idempotent no-op that is not deterministically reachable in-process without a fragile hack (see testing rules), while a store failure lands on the covered return below.
		}
		return err
	}

	return nil
}

// SetAccountLapseSignal implements the sync-plane half of the
// entitlement-lapse bridge contract (POST /managed/accounts/{account_id}/
// premium, {"active": bool}):
//
//   - active == false records accountID's lapse (db.Store.SetAccountLapsed)
//     and immediately revokes every still-valid session it holds — owner
//     decision: no entitlement, no sync. The encrypted data itself is left
//     alone; it waits out LapsedAccountSweepService's grace period.
//   - active == true retracts a previously recorded lapse marker
//     (db.Store.ClearAccountLapse) — e.g. a managed-side false positive
//     caught before the account's next session mint — WITHOUT touching
//     premium_active or sessions. Turning premium_active back on and
//     re-issuing a session both remain CreateManagedSession's job, so a bare
//     retraction here can never grant sync access on its own.
//
// Idempotent: replaying the SAME active value again is a no-op that still
// reports success. In particular, a repeated active=false can never push the
// recorded lapse timestamp forward — SetAccountLapsed preserves whichever
// lapsed_at was recorded first — so replay can never re-extend the purge
// grace deadline.
//
// An account this server has never heard of, or one that vanished between
// the lookup and the write, is treated the same as PurgeManagedAccount: a
// benign no-op success, not an error — the managed caller does not need to
// know whether this server has ever seen the account. A self-hosted account
// whose id collides is refused with ErrInvalidManagedAccount and left
// completely untouched, mirroring PurgeManagedAccount's own refusal for the
// same reason: the bridge credential must never be able to affect a
// self-hosted user's account.
func (s *ManagedBridgeService) SetAccountLapseSignal(
	ctx context.Context,
	accountID string,
	active bool,
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

	if active {
		if err := s.store.ClearAccountLapse(ctx, accountID); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				return nil // codecov:ignore -- TOCTOU race: account deleted (or its mode/marker changed) between the lookup above and this clear; an idempotent no-op that is not deterministically reachable in-process without a fragile hack (see testing rules), while a store failure lands on the covered return below.
			}
			return err
		}
		return nil
	}

	if err := s.store.SetAccountLapsed(ctx, accountID, s.now().UTC()); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil // codecov:ignore -- TOCTOU race: account deleted (or its mode changed) between the lookup above and this write; an idempotent no-op that is not deterministically reachable in-process without a fragile hack (see testing rules), while a store failure lands on the covered return below.
		}
		return err
	}

	if err := s.store.DeleteAllSessionsForAccount(ctx, accountID); err != nil {
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
