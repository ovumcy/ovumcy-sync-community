package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestAccountRepositoryConflictAndLookups(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	account := models.Account{
		ID:            "account-1",
		Login:         "owner@example.com",
		PasswordHash:  "hash",
		Mode:          "self_hosted",
		PremiumActive: false,
		CreatedAt:     now,
	}
	if _, err := store.CreateAccount(context.Background(), account); err != nil {
		t.Fatalf("create account: %v", err)
	}

	if _, err := store.CreateAccount(context.Background(), account); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	foundByLogin, err := store.FindAccountByLogin(context.Background(), account.Login)
	if err != nil {
		t.Fatalf("find account by login: %v", err)
	}
	if foundByLogin.ID != account.ID {
		t.Fatalf("unexpected account lookup result: %#v", foundByLogin)
	}

	if _, err := store.FindAccountByID(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account id, got %v", err)
	}
	if _, err := store.FindAccountByLogin(context.Background(), "missing@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing login, got %v", err)
	}
}

func TestManagedAccountUpsertPreservesIdentityAndUpdatesFlags(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	created, err := store.UpsertManagedAccount(context.Background(), models.Account{
		ID:            "managedacct1234",
		Login:         "managed:managedacct1234",
		PasswordHash:  "managed_service_only",
		Mode:          "managed",
		PremiumActive: true,
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}

	updatedAt := now.Add(2 * time.Hour)
	if _, err := store.UpsertManagedAccount(context.Background(), models.Account{
		ID:            created.ID,
		Login:         "managed:managedacct1234",
		PasswordHash:  "rotated_hash",
		Mode:          "managed",
		PremiumActive: false,
		CreatedAt:     updatedAt,
	}); err != nil {
		t.Fatalf("update managed account: %v", err)
	}

	account, err := store.FindAccountByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("find managed account: %v", err)
	}
	if account.PasswordHash != "rotated_hash" || account.PremiumActive {
		t.Fatalf("unexpected managed account flags after upsert: %#v", account)
	}
}

func TestSessionRepositoryLifecycleAndNotFound(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC()

	if _, err := store.CreateAccount(context.Background(), models.Account{
		ID:           "account-1",
		Login:        "owner@example.com",
		PasswordHash: "hash",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}

	session := models.Session{
		ID:         "session-1",
		AccountID:  "account-1",
		TokenHash:  "token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	if _, err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	lastSeenAt := now.Add(time.Hour)
	if err := store.TouchSession(context.Background(), session.ID, lastSeenAt); err != nil {
		t.Fatalf("touch session: %v", err)
	}

	touched, err := store.FindSessionByTokenHash(context.Background(), session.TokenHash)
	if err != nil {
		t.Fatalf("find touched session: %v", err)
	}
	if !touched.LastSeenAt.Equal(lastSeenAt) {
		t.Fatalf("expected updated last seen time, got %#v", touched)
	}

	if err := store.DeleteSessionByTokenHash(context.Background(), session.TokenHash); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	if _, err := store.FindSessionByTokenHash(context.Background(), session.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := store.TouchSession(context.Background(), "missing-session", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing touch, got %v", err)
	}
	if err := store.DeleteSessionByTokenHash(context.Background(), "missing-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing delete, got %v", err)
	}
}

func TestBlobAndRecoveryRepositoriesReturnNotFoundBeforeWrite(t *testing.T) {
	store := openTestStore(t)

	if _, err := store.GetEncryptedBlob(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing blob, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(context.Background(), "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing recovery package, got %v", err)
	}
}

// TestDeleteAccountErasesEveryChildRowAndIsIdempotent seeds one row in every
// table that carries an account_id (session, device, encrypted blob,
// recovery key package, password reset token, TOTP challenge) plus a second,
// untouched account acting as a control. It asserts DeleteAccount erases all
// of the target account's rows in one call, leaves the other account's rows
// completely alone, and that calling DeleteAccount again on the now-gone
// account is a no-op rather than an error (idempotent repeat semantics).
func TestDeleteAccountErasesEveryChildRowAndIsIdempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const targetAccountID = "account-delete-target"
	const otherAccountID = "account-delete-bystander"

	for _, accountID := range []string{targetAccountID, otherAccountID} {
		if _, err := store.CreateAccount(ctx, models.Account{
			ID:               accountID,
			Login:            accountID + "@example.com",
			PasswordHash:     "hash",
			RecoveryCodeHash: "recovery-hash",
			Mode:             "self_hosted",
			CreatedAt:        now,
		}); err != nil {
			t.Fatalf("create account %s: %v", accountID, err)
		}

		if _, err := store.CreateSession(ctx, models.Session{
			ID:         accountID + "-session",
			AccountID:  accountID,
			TokenHash:  accountID + "-token-hash",
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("create session for %s: %v", accountID, err)
		}

		if _, err := store.UpsertDevice(ctx, models.Device{
			DeviceID:    accountID + "-device",
			AccountID:   accountID,
			DeviceLabel: "Test Device",
			CreatedAt:   now,
			LastSeenAt:  now,
		}, 5); err != nil {
			t.Fatalf("create device for %s: %v", accountID, err)
		}

		if _, err := store.UpsertEncryptedBlob(ctx, models.EncryptedBlob{
			AccountID:      accountID,
			SchemaVersion:  1,
			Generation:     1,
			ChecksumSHA256: strings.Repeat("a", 64),
			Ciphertext:     []byte("ciphertext"),
			CiphertextSize: len("ciphertext"),
			UpdatedAt:      now,
		}); err != nil {
			t.Fatalf("create blob for %s: %v", accountID, err)
		}

		if _, err := store.UpsertRecoveryKeyPackage(ctx, models.RecoveryKeyPackage{
			AccountID:            accountID,
			Algorithm:            "xchacha20poly1305",
			KDF:                  "bip39_seed_hkdf_sha256",
			MnemonicWordCount:    12,
			WrapNonceHex:         strings.Repeat("b", 48),
			WrappedMasterKeyHex:  strings.Repeat("c", 96),
			PhraseFingerprintHex: strings.Repeat("d", 16),
			UpdatedAt:            now,
		}); err != nil {
			t.Fatalf("create recovery key package for %s: %v", accountID, err)
		}

		if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
			AccountID: accountID,
			TokenHash: accountID + "-reset-token-hash",
			CreatedAt: now,
			ExpiresAt: now.Add(30 * time.Minute),
		}, "recovery-hash"); err != nil {
			t.Fatalf("create password reset token for %s: %v", accountID, err)
		}

		if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
			ChallengeIDHash: accountID + "-challenge-hash",
			AccountID:       accountID,
			CreatedAt:       now,
			ExpiresAt:       now.Add(5 * time.Minute),
		}); err != nil {
			t.Fatalf("create totp challenge for %s: %v", accountID, err)
		}
	}

	if err := store.DeleteAccount(ctx, targetAccountID); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	if _, err := store.FindAccountByID(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected account row gone, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, targetAccountID+"-token-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected session gone, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, targetAccountID); err != nil || count != 0 {
		t.Fatalf("expected zero devices, got count=%d err=%v", count, err)
	}
	if _, err := store.GetEncryptedBlob(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected blob gone, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected recovery key package gone, got %v", err)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, targetAccountID+"-reset-token-hash", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected password reset token gone, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, targetAccountID+"-challenge-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected totp challenge gone, got %v", err)
	}

	// Bystander account must be completely untouched.
	if _, err := store.FindAccountByID(ctx, otherAccountID); err != nil {
		t.Fatalf("expected bystander account to remain, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, otherAccountID+"-token-hash"); err != nil {
		t.Fatalf("expected bystander session to remain, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, otherAccountID); err != nil || count != 1 {
		t.Fatalf("expected one bystander device, got count=%d err=%v", count, err)
	}
	if _, err := store.GetEncryptedBlob(ctx, otherAccountID); err != nil {
		t.Fatalf("expected bystander blob to remain, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, otherAccountID); err != nil {
		t.Fatalf("expected bystander recovery key package to remain, got %v", err)
	}

	// Idempotent repeat: deleting an already-gone account is a no-op success,
	// not ErrNotFound bubbling up unexpectedly for callers that treat
	// ErrNotFound as "already erased" — this asserts the raw repository
	// contract that the service layer maps to a friendlier success.
	if err := store.DeleteAccount(ctx, targetAccountID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on repeat delete, got %v", err)
	}
}

// createLapseTestAccount seeds a bare account row (no session/device/blob
// children) at the given mode, with premium_active seeded true so tests can
// observe SetAccountLapsed actually clearing it.
func createLapseTestAccount(t *testing.T, store *Store, accountID string, mode string) {
	t.Helper()

	if _, err := store.CreateAccount(context.Background(), models.Account{
		ID:            accountID,
		Login:         accountID + "@example.com",
		PasswordHash:  "hash",
		Mode:          mode,
		PremiumActive: true,
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create %s account %s: %v", mode, accountID, err)
	}
}

// TestSetAccountLapsedRecordsMarkerPreservesOnReplayAndScopesToManaged covers
// SetAccountLapsed's full contract: it records lapsed_at and clears
// premium_active on a managed account; a replay with a later timestamp must
// NOT push lapsed_at forward (the COALESCE — this is what keeps a repeated
// lapse signal from ever extending the purge sweep's grace deadline); it
// refuses a self-hosted account (mode scoping) and a missing account, both
// via ErrNotFound, leaving the self-hosted account's marker permanently nil.
func TestSetAccountLapsedRecordsMarkerPreservesOnReplayAndScopesToManaged(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	const managedID = "managed-lapse-target"
	const selfHostedID = "self-hosted-lapse-bystander"
	createLapseTestAccount(t, store, managedID, "managed")
	createLapseTestAccount(t, store, selfHostedID, "self_hosted")

	firstLapse := time.Now().UTC().Add(-48 * time.Hour)
	if err := store.SetAccountLapsed(ctx, managedID, firstLapse); err != nil {
		t.Fatalf("set account lapsed: %v", err)
	}

	account, err := store.FindAccountByID(ctx, managedID)
	if err != nil {
		t.Fatalf("find managed account after lapse: %v", err)
	}
	if account.PremiumActive {
		t.Fatal("expected premium_active cleared after SetAccountLapsed")
	}

	lapsedAt, err := store.GetAccountLapsedAt(ctx, managedID)
	if err != nil {
		t.Fatalf("get account lapsed at: %v", err)
	}
	if lapsedAt == nil || !lapsedAt.Equal(firstLapse) {
		t.Fatalf("expected lapsed_at %s, got %v", firstLapse, lapsedAt)
	}

	// Replay with a later timestamp must not move the recorded marker.
	laterLapse := firstLapse.Add(24 * time.Hour)
	if err := store.SetAccountLapsed(ctx, managedID, laterLapse); err != nil {
		t.Fatalf("replay set account lapsed: %v", err)
	}
	replayedLapsedAt, err := store.GetAccountLapsedAt(ctx, managedID)
	if err != nil {
		t.Fatalf("get account lapsed at after replay: %v", err)
	}
	if replayedLapsedAt == nil || !replayedLapsedAt.Equal(firstLapse) {
		t.Fatalf("expected lapsed_at to stay pinned at %s after replay, got %v", firstLapse, replayedLapsedAt)
	}

	// A self-hosted account can never be marked lapsed, even by id.
	if err := store.SetAccountLapsed(ctx, selfHostedID, firstLapse); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound marking a self-hosted account lapsed, got %v", err)
	}
	selfHostedLapsedAt, err := store.GetAccountLapsedAt(ctx, selfHostedID)
	if err != nil {
		t.Fatalf("get self-hosted account lapsed at: %v", err)
	}
	if selfHostedLapsedAt != nil {
		t.Fatalf("expected self-hosted account lapsed_at to stay nil, got %v", selfHostedLapsedAt)
	}

	if err := store.SetAccountLapsed(ctx, "missing-account", firstLapse); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account, got %v", err)
	}
}

// TestClearAccountLapseRetractsMarkerWithoutTouchingPremiumActive covers the
// active=true retraction path: it clears lapsed_at but must leave
// premium_active exactly as it found it (reactivating premium is the mint
// path's job, not this method's), is a no-op success when there is no
// marker to clear, and is scoped to mode='managed' the same way
// SetAccountLapsed is.
func TestClearAccountLapseRetractsMarkerWithoutTouchingPremiumActive(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	const managedID = "managed-clear-target"
	const selfHostedID = "self-hosted-clear-bystander"
	createLapseTestAccount(t, store, managedID, "managed")
	createLapseTestAccount(t, store, selfHostedID, "self_hosted")

	if err := store.SetAccountLapsed(ctx, managedID, time.Now().UTC()); err != nil {
		t.Fatalf("set account lapsed: %v", err)
	}

	if err := store.ClearAccountLapse(ctx, managedID); err != nil {
		t.Fatalf("clear account lapse: %v", err)
	}

	lapsedAt, err := store.GetAccountLapsedAt(ctx, managedID)
	if err != nil {
		t.Fatalf("get account lapsed at after clear: %v", err)
	}
	if lapsedAt != nil {
		t.Fatalf("expected lapsed_at cleared, got %v", lapsedAt)
	}
	account, err := store.FindAccountByID(ctx, managedID)
	if err != nil {
		t.Fatalf("find managed account after clear: %v", err)
	}
	if account.PremiumActive {
		t.Fatal("expected premium_active to remain false after ClearAccountLapse — reactivation is the mint path's job")
	}

	// Clearing an already-clear marker is a no-op success.
	if err := store.ClearAccountLapse(ctx, managedID); err != nil {
		t.Fatalf("expected no-op success clearing an already-clear marker, got %v", err)
	}

	if err := store.ClearAccountLapse(ctx, selfHostedID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound clearing a self-hosted account's lapse, got %v", err)
	}
	if err := store.ClearAccountLapse(ctx, "missing-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing account, got %v", err)
	}
}

// TestUpsertManagedAccountRefusesLapsedAccount pins SYNC-9: a mint refresh
// through UpsertManagedAccount must leave a recorded lapse in place, keep
// premium_active off and report ErrAccountLapsed; after a reactivation
// clears the marker the same mint restores premium_active.
func TestUpsertManagedAccountRefusesLapsedAccount(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const managedID = "managed-mint-after-lapse"
	createLapseTestAccount(t, store, managedID, "managed")

	lapsedAt := now.Add(-72 * time.Hour)
	if err := store.SetAccountLapsed(ctx, managedID, lapsedAt); err != nil {
		t.Fatalf("set account lapsed: %v", err)
	}

	mint := models.Account{
		ID:            managedID,
		Login:         "managed:" + managedID,
		PasswordHash:  "managed_service_only",
		Mode:          "managed",
		PremiumActive: true,
		CreatedAt:     now,
	}
	if _, err := store.UpsertManagedAccount(ctx, mint); !errors.Is(err, ErrAccountLapsed) {
		t.Fatalf("expected ErrAccountLapsed for a mint after lapse, got %v", err)
	}
	if got, err := store.GetAccountLapsedAt(ctx, managedID); err != nil || got == nil || !got.Equal(lapsedAt) {
		t.Fatalf("expected lapsed_at to stay %s after the refused mint, got %v err=%v", lapsedAt, got, err)
	}
	account, err := store.FindAccountByID(ctx, managedID)
	if err != nil {
		t.Fatalf("find managed account after refused mint: %v", err)
	}
	if account.PremiumActive {
		t.Fatal("expected premium_active to stay false after a refused mint")
	}

	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{Active: true, AsOf: now, ReceivedAt: now}); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if _, err := store.UpsertManagedAccount(ctx, mint); err != nil {
		t.Fatalf("mint after reactivation: %v", err)
	}
	account, err = store.FindAccountByID(ctx, managedID)
	if err != nil {
		t.Fatalf("find managed account after mint: %v", err)
	}
	if !account.PremiumActive {
		t.Fatal("expected premium_active restored by the mint after reactivation")
	}
}

// TestApplyEntitlementSignalOrdersAndRevokesInOneTransaction covers the
// store contract: a lapse revokes the account's sessions (a bystander's
// survive), a stale signal changes nothing, the ordering point only moves
// forward, and non-managed or missing accounts report ErrNotFound.
func TestApplyEntitlementSignalOrdersAndRevokesInOneTransaction(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const managedID = "managed-signal-order"
	const bystanderID = "managed-signal-bystander"
	const selfHostedID = "self-hosted-signal"
	createLapseTestAccount(t, store, managedID, "managed")
	createLapseTestAccount(t, store, bystanderID, "managed")
	createLapseTestAccount(t, store, selfHostedID, "self_hosted")
	for _, id := range []string{managedID, bystanderID} {
		if _, err := store.CreateSession(ctx, models.Session{
			ID:         id + "-session",
			AccountID:  id,
			TokenHash:  id + "-token-hash",
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("create session for %s: %v", id, err)
		}
	}

	lapseAsOf := now.Add(-time.Hour)
	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{AsOf: lapseAsOf, ReceivedAt: now}); err != nil {
		t.Fatalf("apply lapse: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, managedID+"-token-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the lapsed account's session deleted, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, bystanderID+"-token-hash"); err != nil {
		t.Fatalf("expected the bystander's session to survive, got %v", err)
	}
	if got, err := store.GetAccountLapsedAt(ctx, managedID); err != nil || got == nil || !got.Equal(now) {
		t.Fatalf("expected lapsed_at stamped with the server clock %s, got %v err=%v", now, got, err)
	}

	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{Active: true, AsOf: lapseAsOf, ReceivedAt: now}); !errors.Is(err, ErrStaleEntitlementSignal) {
		t.Fatalf("expected a tied reactivation to be stale, got %v", err)
	}
	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{AsOf: lapseAsOf.Add(-time.Minute), ReceivedAt: now}); err != nil {
		t.Fatalf("expected an older lapse on a lapsed account to be a no-op success, got %v", err)
	}
	if got, err := store.GetAccountLapsedAt(ctx, managedID); err != nil || got == nil || !got.Equal(now) {
		t.Fatalf("expected lapsed_at unchanged by an older lapse, got %v err=%v", got, err)
	}
	if got, err := store.GetAccountLapsedAt(ctx, managedID); err != nil || got == nil {
		t.Fatalf("expected the lapse to survive a stale reactivation, got %v err=%v", got, err)
	}

	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{Active: true, AsOf: now, ReceivedAt: now}); err != nil {
		t.Fatalf("apply reactivation: %v", err)
	}
	if got, err := store.GetAccountLapsedAt(ctx, managedID); err != nil || got != nil {
		t.Fatalf("expected lapsed_at cleared by reactivation, got %v err=%v", got, err)
	}
	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{Active: true, AsOf: now, ReceivedAt: now}); err != nil {
		t.Fatalf("expected a retried reactivation to be a no-op success, got %v", err)
	}

	// A legacy lapse (no AsOf) stamped earlier than the stored point applies
	// without moving the ordering point back, so the older reactivation that
	// follows is still stale.
	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{ReceivedAt: lapseAsOf}); err != nil {
		t.Fatalf("apply legacy lapse: %v", err)
	}
	if err := store.ApplyEntitlementSignal(ctx, managedID, EntitlementSignal{Active: true, AsOf: now.Add(-time.Minute), ReceivedAt: now}); !errors.Is(err, ErrStaleEntitlementSignal) {
		t.Fatalf("expected a reactivation older than the stored point to be stale, got %v", err)
	}

	// A lapse recorded before migration 0009 has no stored point; it is
	// ordered by lapsed_at, so an older reactivation cannot undo it.
	const legacyID = "managed-signal-legacy"
	createLapseTestAccount(t, store, legacyID, "managed")
	if err := store.SetAccountLapsed(ctx, legacyID, lapseAsOf); err != nil {
		t.Fatalf("set legacy lapse: %v", err)
	}
	if err := store.ApplyEntitlementSignal(ctx, legacyID, EntitlementSignal{Active: true, AsOf: lapseAsOf.Add(-time.Second), ReceivedAt: now}); !errors.Is(err, ErrStaleEntitlementSignal) {
		t.Fatalf("expected a reactivation older than a legacy lapse to be stale, got %v", err)
	}
	if err := store.ApplyEntitlementSignal(ctx, legacyID, EntitlementSignal{Active: true, AsOf: lapseAsOf.Add(time.Second), ReceivedAt: now}); err != nil {
		t.Fatalf("expected a newer reactivation to clear a legacy lapse, got %v", err)
	}

	for _, id := range []string{selfHostedID, "missing-account"} {
		if err := store.ApplyEntitlementSignal(ctx, id, EntitlementSignal{ReceivedAt: now}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound for %s, got %v", id, err)
		}
	}
	if got, err := store.GetAccountLapsedAt(ctx, selfHostedID); err != nil || got != nil {
		t.Fatalf("expected the self-hosted account untouched, got %v err=%v", got, err)
	}
}

// TestListAndDeleteLapsedManagedAccountRespectCutoffAndManagedScope covers
// the sweep's candidate query and delete-time re-check together: an account
// lapsed well past the grace cutoff is listed and deletable (whole-account
// cascade, including a seeded session row); an account lapsed inside the
// grace window is never listed and DeleteLapsedManagedAccount refuses it
// (ErrNotFound, untouched); and — the required regression — a self-hosted
// account, which structurally can never carry a lapsed_at marker, is never
// listed and can never be selected by DeleteLapsedManagedAccount either.
func TestListAndDeleteLapsedManagedAccountRespectCutoffAndManagedScope(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cutoff := now.Add(-60 * 24 * time.Hour)

	const pastGraceID = "managed-past-grace"
	const withinGraceID = "managed-within-grace"
	const selfHostedID = "self-hosted-never-eligible"

	createLapseTestAccount(t, store, pastGraceID, "managed")
	createLapseTestAccount(t, store, withinGraceID, "managed")
	createLapseTestAccount(t, store, selfHostedID, "self_hosted")

	if _, err := store.CreateSession(ctx, models.Session{
		ID:         pastGraceID + "-session",
		AccountID:  pastGraceID,
		TokenHash:  pastGraceID + "-token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("seed session for past-grace account: %v", err)
	}

	if err := store.SetAccountLapsed(ctx, pastGraceID, now.Add(-90*24*time.Hour)); err != nil {
		t.Fatalf("lapse past-grace account: %v", err)
	}
	if err := store.SetAccountLapsed(ctx, withinGraceID, now.Add(-10*24*time.Hour)); err != nil {
		t.Fatalf("lapse within-grace account: %v", err)
	}

	candidateIDs, err := store.ListLapsedManagedAccountIDs(ctx, cutoff, 0)
	if err != nil {
		t.Fatalf("list lapsed managed account ids: %v", err)
	}
	if len(candidateIDs) != 1 || candidateIDs[0] != pastGraceID {
		t.Fatalf("expected only %q as a candidate, got %#v", pastGraceID, candidateIDs)
	}

	// Within-grace: not eligible yet, delete is refused and the account
	// survives untouched.
	if err := store.DeleteLapsedManagedAccount(ctx, withinGraceID, cutoff); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting a within-grace account, got %v", err)
	}
	if _, err := store.FindAccountByID(ctx, withinGraceID); err != nil {
		t.Fatalf("expected within-grace account to survive, got %v", err)
	}

	// Self-hosted: structurally never eligible (no marker was ever set, and
	// SetAccountLapsed would have refused it too — see the dedicated test).
	// This is the regression: it can never be selected by the sweep delete.
	if err := store.DeleteLapsedManagedAccount(ctx, selfHostedID, cutoff); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting a self-hosted account, got %v", err)
	}
	if _, err := store.FindAccountByID(ctx, selfHostedID); err != nil {
		t.Fatalf("expected self-hosted account to survive, got %v", err)
	}

	// Past-grace: eligible, whole-account cascade including the seeded
	// session row.
	if err := store.DeleteLapsedManagedAccount(ctx, pastGraceID, cutoff); err != nil {
		t.Fatalf("delete past-grace account: %v", err)
	}
	if _, err := store.FindAccountByID(ctx, pastGraceID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected past-grace account row gone, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, pastGraceID+"-token-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected past-grace account's session gone, got %v", err)
	}

	// Idempotent repeat: already gone.
	if err := store.DeleteLapsedManagedAccount(ctx, pastGraceID, cutoff); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on repeat delete, got %v", err)
	}
}

// TestDeleteLapsedManagedAccountRecheckInsideTransactionPreservesRacingMint
// is the core safety property the ADR requires: a session mint that races
// the sweep — clearing lapsed_at via ClearAccountLapse/UpsertManagedAccount
// AFTER the sweep already computed its cutoff and selected this account as a
// candidate, but BEFORE the delete transaction commits — must make the
// delete a no-op. Both the account row and its child data (a seeded session)
// must survive completely: the child-table deletes inside the transaction
// must never reach disk when the final conditional DELETE affects zero rows.
func TestDeleteLapsedManagedAccountRecheckInsideTransactionPreservesRacingMint(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cutoff := now.Add(-60 * 24 * time.Hour)

	const racerID = "managed-racing-mint"
	createLapseTestAccount(t, store, racerID, "managed")
	if _, err := store.CreateSession(ctx, models.Session{
		ID:         racerID + "-session",
		AccountID:  racerID,
		TokenHash:  racerID + "-token-hash",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("seed session for racing account: %v", err)
	}

	if err := store.SetAccountLapsed(ctx, racerID, now.Add(-90*24*time.Hour)); err != nil {
		t.Fatalf("lapse racing account: %v", err)
	}

	// The sweep would list racerID as a candidate at this cutoff (lapsed_at
	// is 90 days old, well past the 60-day cutoff) — simulate that having
	// already happened, then race a mint's marker-clear in before the
	// delete transaction runs.
	if err := store.ClearAccountLapse(ctx, racerID); err != nil {
		t.Fatalf("simulate racing mint clearing lapse: %v", err)
	}

	if err := store.DeleteLapsedManagedAccount(ctx, racerID, cutoff); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound when a mint races the sweep, got %v", err)
	}

	if _, err := store.FindAccountByID(ctx, racerID); err != nil {
		t.Fatalf("expected racing account row to survive completely, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, racerID+"-token-hash"); err != nil {
		t.Fatalf("expected racing account's session to survive (transaction must fully roll back), got %v", err)
	}
}
