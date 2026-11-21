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

// ErrInvalidEntitlementSignal: a lapse or reactivation without an as-of instant, or
// an as-of instant before the Unix epoch or beyond maxEntitlementSignalSkew
// ahead of this server's clock.
var ErrInvalidEntitlementSignal = errors.New("invalid_entitlement_signal")

// ErrStaleEntitlementSignal: a newer lapse or reactivation has already been
// applied to the account, so this one changed nothing.
var ErrStaleEntitlementSignal = errors.New("stale_entitlement_signal")

// ErrManagedAccountNotFound: a bridge re-key names no managed account here —
// none at all, or a self-hosted one, answered alike.
var ErrManagedAccountNotFound = errors.New("managed_account_not_found")

// ErrRecoveryKeyConflict: a bridge re-key whose expected fingerprint is not
// the stored package's (or no package is stored); nothing was written.
var ErrRecoveryKeyConflict = errors.New("recovery_key_conflict")

// maxEntitlementSignalSkew bounds how far a signal's as-of may run ahead of
// this server's clock: the stored ordering point only moves forward, so one
// far-future as-of would otherwise mark every later lapse stale.
const maxEntitlementSignalSkew = 5 * time.Minute

// managedAccountIDPattern is matched on the raw id, before lowercasing:
// strings.ToLower folds some non-ASCII runes into ASCII (U+212A KELVIN SIGN
// to k), and a (?i) flag would accept that rune too.
var managedAccountIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$`)

// normalizeManagedAccountID trims ASCII whitespace from the bridge's account
// id, refuses one outside the ASCII pattern (ErrInvalidManagedAccount) and
// lowercases the rest. strings.TrimSpace would also strip Unicode spaces
// (U+00A0, U+3000), letting a non-ASCII spelling name an ASCII account.
func normalizeManagedAccountID(raw string) (string, error) {
	accountID := strings.Trim(raw, " \t\r\n")
	if !managedAccountIDPattern.MatchString(accountID) {
		return "", ErrInvalidManagedAccount
	}
	return strings.ToLower(accountID), nil
}

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
	accountID, err := normalizeManagedAccountID(accountID)
	if err != nil {
		return AuthResult{}, err
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

	return s.auth.CreateSessionForUnlapsedManagedAccount(ctx, accountID)
}

// PurgeManagedAccount permanently erases the managed account and every row
// this server holds for it — sessions, devices, the encrypted sync blob, the
// wrapped recovery-key package, pending password-reset tokens, and TOTP
// challenges — via Store.DeleteManagedAccount's single transaction. It is the
// sync-plane half of managed-cloud account deletion: the separate managed
// service calls it before purging its own database so no ciphertext is ever
// orphaned here.
//
// The id is matched raw against accounts.id after the same normalization and
// pattern gate as CreateManagedSession — the "managed:" namespace lives only
// in the login column, never in the id. Only mode=managed accounts are
// erasable through this path: a self-hosted account whose id matches is left
// untouched, so the bridge credential can never erase a self-hosted user's
// data, and gets the nil an absent id gets, so the answer never reveals that
// a self-hosted account exists.
//
// Idempotent: an account that never existed or is already gone (including a
// concurrent-delete race) returns nil, so the managed caller can safely retry
// after a dropped response.
func (s *ManagedBridgeService) PurgeManagedAccount(
	ctx context.Context,
	accountID string,
) error {
	accountID, err := normalizeManagedAccountID(accountID)
	if err != nil {
		return err
	}

	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil
		}
		return err
	}
	if account.Mode != "managed" {
		return nil
	}

	if err := s.store.DeleteManagedAccount(ctx, accountID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil // codecov:ignore -- TOCTOU race: account deleted between the lookup above and this delete; an idempotent no-op that is not deterministically reachable in-process without a fragile hack (see testing rules), while a store failure lands on the covered return below.
		}
		return err
	}

	return nil
}

// RevokeManagedAccountSessions deletes every sync session of the managed
// account (POST /managed/accounts/{account_id}/sessions/revoke). The managed
// service calls it when the account's own credentials change or an operator
// revokes its sessions, so a sync session minted earlier does not outlive
// them; the next CreateManagedSession issues a fresh one.
//
// The id gets the same normalization and pattern gate as PurgeManagedAccount.
// Only sessions go: the blob, devices, recovery-key package and lapse state
// are left as they are. A managed account has no recovery code, so it never
// holds a password-reset token to delete.
//
// An unknown account, a managed account with no sessions, and a self-hosted
// account whose id matches all return nil and change nothing — the store's
// delete is scoped to mode='managed' — so the answer never reveals whether a
// self-hosted account exists, and a repeated call is safe.
func (s *ManagedBridgeService) RevokeManagedAccountSessions(
	ctx context.Context,
	accountID string,
) error {
	accountID, err := normalizeManagedAccountID(accountID)
	if err != nil {
		return err
	}

	return s.store.DeleteManagedAccountSessions(ctx, accountID)
}

// ReplaceManagedRecoveryKeyPackage implements the bridge re-key
// (PUT /managed/accounts/{account_id}/recovery-key): it stores a new wrapped
// recovery-key package for a managed account, replacing the stored one. A
// managed session can only store a first package, since a managed account has
// no password to step up with; ovumcy-managed calls this after its own
// re-authentication of the owner. The package passes the same validation as
// the session route; sessions, devices, the blob and lapse state are left as
// they are.
//
// The id gets the same normalization and pattern gate as PurgeManagedAccount.
// An unknown account and a self-hosted one whose id matches both answer
// ErrManagedAccountNotFound and write nothing: the bridge never writes to a
// self-hosted account, and the answer does not tell the two apart.
//
// A non-nil expectedFingerprint (normalized and checked like the package's
// phrase_fingerprint_hex, else ErrInvalidRecoveryPackage) makes the replace
// conditional on the stored package carrying that fingerprint: otherwise
// ErrRecoveryKeyConflict and nothing is written, unless the stored package
// already equals the new one. nil keeps the unconditional replace, so a caller
// that does not send it yet works unchanged.
func (s *ManagedBridgeService) ReplaceManagedRecoveryKeyPackage(
	ctx context.Context,
	accountID string,
	input PutRecoveryKeyPackageInput,
	expectedFingerprint *string,
) error {
	accountID, err := normalizeManagedAccountID(accountID)
	if err != nil {
		return err
	}

	recoveryKeyPackage := normalizeRecoveryKeyPackage(accountID, input)
	if err := validateRecoveryKeyPackage(recoveryKeyPackage); err != nil {
		return err
	}
	if expectedFingerprint != nil {
		normalized := strings.TrimSpace(strings.ToLower(*expectedFingerprint))
		if len(normalized) != 16 || !lowercaseHexPattern.MatchString(normalized) {
			return ErrInvalidRecoveryPackage
		}
		expectedFingerprint = &normalized
	}
	recoveryKeyPackage.UpdatedAt = s.now().UTC()

	err = s.store.ReplaceManagedRecoveryKeyPackageExpecting(ctx, recoveryKeyPackage, expectedFingerprint)
	switch {
	case errors.Is(err, db.ErrNotFound):
		return ErrManagedAccountNotFound
	case errors.Is(err, db.ErrRecoveryKeyConflict):
		return ErrRecoveryKeyConflict
	}
	return err
}

// SetAccountLapseSignal implements the sync-plane half of the
// entitlement-lapse bridge contract (POST /managed/accounts/{account_id}/
// premium, {"active": bool, "as_of": RFC 3339}). The sync server stores the
// state the managed service reports; it never decides entitlement itself.
//
//   - active == false records accountID's lapse and, in the same
//     transaction, revokes every session it holds — no entitlement, no
//     sync. The encrypted data waits out LapsedAccountSweepService's grace
//     period.
//   - active == true is the only way back from a lapse: it clears the
//     marker WITHOUT touching premium_active or sessions, so the next
//     CreateManagedSession restores premium and issues the session.
//
// asOf is required for both. A reactivation must be provably newer than the
// lapse it undoes, and a lapse ordered by this server's receive time instead
// could be judged newer than a reactivation the managed side observed later,
// whose clock runs behind ours, and so purge an account that resubscribed.
//
// Signals are ordered by asOf (db.Store.ApplyEntitlementSignal): one older
// than an already-applied signal returns ErrStaleEntitlementSignal and
// changes nothing, so a delayed or retried reactivation can never undo a
// newer lapse. Replaying an identical lapse is a no-op success that never
// pushes lapsed_at forward.
//
// For an account this server has never heard of, or one that vanished
// between the lookup and the write, the call returns nil (the route answers
// `lapse_recorded`) and stores nothing: no lapse marker is kept, so a later
// CreateManagedSession for that id is not refused, and the signal takes
// effect only if it is sent again once the account exists. PurgeManagedAccount
// answers an absent account the same way. A self-hosted account whose id matches gets that same
// nil and is left untouched: the bridge credential must never affect a
// self-hosted user's account, and the answer must not reveal that one exists.
func (s *ManagedBridgeService) SetAccountLapseSignal(
	ctx context.Context,
	accountID string,
	active bool,
	asOf time.Time,
) error {
	accountID, err := normalizeManagedAccountID(accountID)
	if err != nil {
		return err
	}

	now := s.now().UTC()
	if asOf.IsZero() || asOf.Before(time.Unix(0, 0)) || asOf.After(now.Add(maxEntitlementSignalSkew)) {
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
		return nil
	}

	err = s.store.ApplyEntitlementSignal(ctx, accountID, db.EntitlementSignal{
		Active:     active,
		AsOf:       asOf,
		ReceivedAt: now,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, db.ErrInvalidEntitlementSignal):
		return ErrInvalidEntitlementSignal // codecov:ignore -- the as-of check above already refuses a zero instant, so the store's own refusal is a defence in depth the service cannot reach; the store test pins the refusal itself.
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
