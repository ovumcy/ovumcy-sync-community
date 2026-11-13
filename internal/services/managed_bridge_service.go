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

// ErrManagedAccountLapsed: a session mint for an account whose entitlement
// lapse is recorded. Only an ordered reactivation signal clears the lapse.
var ErrManagedAccountLapsed = errors.New("managed_account_lapsed")

// ErrInvalidEntitlementSignal: a reactivation without an as-of instant, or
// an as-of instant before the Unix epoch or beyond maxEntitlementSignalSkew
// ahead of this server's clock.
var ErrInvalidEntitlementSignal = errors.New("invalid_entitlement_signal")

// ErrStaleEntitlementSignal: a newer lapse or reactivation has already been
// applied to the account, so this one changed nothing.
var ErrStaleEntitlementSignal = errors.New("stale_entitlement_signal")

// maxEntitlementSignalSkew bounds how far a signal's as-of may run ahead of
// this server's clock: the stored ordering point only moves forward, so one
// far-future as-of would otherwise mark every later lapse stale.
const maxEntitlementSignalSkew = 5 * time.Minute

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
		if errors.Is(err, db.ErrAccountLapsed) {
			return AuthResult{}, ErrManagedAccountLapsed
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
// premium, {"active": bool, "as_of": RFC 3339}). The sync server stores the
// state the managed service reports; it never decides entitlement itself.
//
//   - active == false records accountID's lapse and, in the same
//     transaction, revokes every session it holds — no entitlement, no
//     sync. The encrypted data waits out LapsedAccountSweepService's grace
//     period. asOf is optional here: a lapse without one is never stale.
//   - active == true is the only way back from a lapse: it clears the
//     marker WITHOUT touching premium_active or sessions, so the next
//     CreateManagedSession restores premium and issues the session. asOf is
//     required, because a reactivation must be provably newer than the lapse
//     it undoes.
//
// Signals are ordered by asOf (db.Store.ApplyEntitlementSignal): one older
// than an already-applied signal returns ErrStaleEntitlementSignal and
// changes nothing, so a delayed or retried reactivation can never undo a
// newer lapse. Replaying an identical lapse is a no-op success that never
// pushes lapsed_at forward.
//
// An account this server has never heard of, or one that vanished between
// the lookup and the write, is a benign no-op success, as in
// PurgeManagedAccount. A self-hosted account whose id collides is refused
// with ErrInvalidManagedAccount and left untouched: the bridge credential
// must never affect a self-hosted user's account.
func (s *ManagedBridgeService) SetAccountLapseSignal(
	ctx context.Context,
	accountID string,
	active bool,
	asOf time.Time,
) error {
	accountID = strings.TrimSpace(strings.ToLower(accountID))
	if !managedAccountIDPattern.MatchString(accountID) {
		return ErrInvalidManagedAccount
	}

	now := s.now().UTC()
	if active && asOf.IsZero() {
		return ErrInvalidEntitlementSignal
	}
	if !asOf.IsZero() && (asOf.Before(time.Unix(0, 0)) || asOf.After(now.Add(maxEntitlementSignalSkew))) {
		return ErrInvalidEntitlementSignal
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

	err = s.store.ApplyEntitlementSignal(ctx, accountID, db.EntitlementSignal{
		Active:     active,
		AsOf:       asOf,
		ReceivedAt: now,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, db.ErrStaleEntitlementSignal):
		return ErrStaleEntitlementSignal
	case errors.Is(err, db.ErrNotFound):
		return nil // codecov:ignore -- TOCTOU race: account deleted (or its mode changed) between the lookup above and this write; an idempotent no-op that is not deterministically reachable in-process without a fragile hack (see testing rules), while a store failure lands on the covered return below.
	default:
		return err
	}
}

func existingOrCreatedAt(account models.Account, fallback time.Time) time.Time {
	if !account.CreatedAt.IsZero() {
		return account.CreatedAt
	}
	return fallback
}
