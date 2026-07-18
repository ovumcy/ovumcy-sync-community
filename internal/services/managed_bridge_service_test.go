package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestManagedBridgeRejectsInvalidAccountID(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	if _, err := bridgeService.CreateManagedSession(context.Background(), "bad"); err != ErrInvalidManagedAccount {
		t.Fatalf("expected ErrInvalidManagedAccount for short id, got %v", err)
	}
}

func TestManagedBridgeRejectsExistingSelfHostedAccount(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	result, err := authService.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := bridgeService.CreateManagedSession(context.Background(), result.AccountID); err != ErrInvalidManagedAccount {
		t.Fatalf("expected ErrInvalidManagedAccount for self-hosted account reuse, got %v", err)
	}
}

func TestManagedBridgePurgeRejectsInvalidAccountID(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	for _, id := range []string{"bad", "invalid*chars!", ""} {
		if err := bridgeService.PurgeManagedAccount(context.Background(), id); !errors.Is(err, ErrInvalidManagedAccount) {
			t.Fatalf("expected ErrInvalidManagedAccount for id %q, got %v", id, err)
		}
	}
}

func TestManagedBridgePurgeErasesBlobDeviceAndSessionThenIsIdempotent(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	ctx := context.Background()
	const accountID = "managedacct1234"

	session, err := bridgeService.CreateManagedSession(ctx, accountID)
	if err != nil {
		t.Fatalf("create managed session: %v", err)
	}

	if _, err := syncService.AttachDevice(ctx, accountID, "device-12345", "Pixel 7"); err != nil {
		t.Fatalf("attach device: %v", err)
	}

	ciphertext := []byte("managed-ciphertext-payload")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, accountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	if _, err := syncService.PutRecoveryKeyPackage(ctx, accountID, PutRecoveryKeyPackageInput{
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: strings.Repeat("c", 16),
	}); err != nil {
		t.Fatalf("put recovery key package: %v", err)
	}

	if _, err := authService.Authenticate(ctx, session.SessionToken); err != nil {
		t.Fatalf("expected managed session valid before purge, got %v", err)
	}

	if err := bridgeService.PurgeManagedAccount(ctx, accountID); err != nil {
		t.Fatalf("purge managed account: %v", err)
	}

	if _, err := authService.Authenticate(ctx, session.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected managed session revoked after purge, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, accountID); err != ErrBlobNotFound {
		t.Fatalf("expected encrypted blob gone after purge, got %v", err)
	}
	if _, err := syncService.GetRecoveryKeyPackage(ctx, accountID); err != ErrRecoveryPackageNotFound {
		t.Fatalf("expected recovery key package gone after purge, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, accountID); err != nil || count != 0 {
		t.Fatalf("expected zero devices after purge, got count=%d err=%v", count, err)
	}
	if _, err := store.FindAccountByID(ctx, accountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected managed account row gone after purge, got %v", err)
	}

	// A repeat purge of the now-missing account must report success so the
	// managed caller can retry after a dropped response.
	if err := bridgeService.PurgeManagedAccount(ctx, accountID); err != nil {
		t.Fatalf("expected idempotent repeat purge to succeed, got %v", err)
	}
}

func TestManagedBridgePurgeUnknownAccountIsIdempotentNoOp(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	if err := bridgeService.PurgeManagedAccount(context.Background(), "neverexisted1234"); err != nil {
		t.Fatalf("expected purge of a never-existed managed account to succeed, got %v", err)
	}
}

func TestManagedBridgePurgeSurfacesAccountLookupStoreError(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	// Close the store so the account lookup fails with a generic store error
	// rather than db.ErrNotFound: the purge must surface it, never report a
	// false idempotent success that would tell the managed caller the account
	// is gone when it may still hold ciphertext.
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err := bridgeService.PurgeManagedAccount(context.Background(), "managedacct1234")
	if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected a store error from the account lookup, got %v", err)
	}
}

func TestManagedBridgePurgeSurfacesAccountDeleteStoreError(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	ctx := context.Background()
	const accountID = "managedacct1234"
	if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
		t.Fatalf("create managed session: %v", err)
	}

	// Drop a child table the account-delete transaction writes to while leaving
	// the accounts row intact: the lookup and managed-mode guard pass, then
	// DeleteAccount fails with a generic store error. The purge must surface it
	// instead of swallowing it as an idempotent no-op.
	dropTable(t, dbPath, "sessions")

	err := bridgeService.PurgeManagedAccount(ctx, accountID)
	if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected a store error from the account deletion, got %v", err)
	}
}

func TestManagedBridgePurgeRefusesSelfHostedAccount(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	ctx := context.Background()
	registered, err := authService.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	ciphertext := []byte("self-hosted-ciphertext")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, registered.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	// The bridge credential must never erase a self-hosted user's data, even
	// when handed that account's raw id.
	if err := bridgeService.PurgeManagedAccount(ctx, registered.AccountID); !errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected ErrInvalidManagedAccount for self-hosted account, got %v", err)
	}

	if _, err := authService.Authenticate(ctx, registered.SessionToken); err != nil {
		t.Fatalf("expected self-hosted session to survive refused purge, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, registered.AccountID); err != nil {
		t.Fatalf("expected self-hosted blob to survive refused purge, got %v", err)
	}
	if _, err := store.FindAccountByID(ctx, registered.AccountID); err != nil {
		t.Fatalf("expected self-hosted account row to survive refused purge, got %v", err)
	}
}

func TestSetAccountLapseSignalRejectsInvalidAccountID(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	for _, id := range []string{"bad", "invalid*chars!", ""} {
		if err := bridgeService.SetAccountLapseSignal(context.Background(), id, false); !errors.Is(err, ErrInvalidManagedAccount) {
			t.Fatalf("expected ErrInvalidManagedAccount for id %q, got %v", id, err)
		}
	}
}

// TestSetAccountLapseSignalRecordsLapseRevokesSessionsAndReplayIsIdempotent
// covers the active=false core contract: it clears premium_active, records
// lapsed_at, and immediately revokes the account's pre-lapse session (owner
// decision: no entitlement, no sync). A replay of the same signal must stay
// idempotent — still succeed, still leave sessions revoked — and critically
// must NOT push the recorded lapsed_at forward, which would silently extend
// the purge sweep's grace deadline every time the signal is repeated.
func TestSetAccountLapseSignalRecordsLapseRevokesSessionsAndReplayIsIdempotent(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	ctx := context.Background()
	const accountID = "managedacct1234"

	session, err := bridgeService.CreateManagedSession(ctx, accountID)
	if err != nil {
		t.Fatalf("create managed session: %v", err)
	}
	if _, err := authService.Authenticate(ctx, session.SessionToken); err != nil {
		t.Fatalf("expected session valid before lapse, got %v", err)
	}

	firstLapse := time.Now().UTC().Add(-time.Hour)
	bridgeService.now = func() time.Time { return firstLapse }

	if err := bridgeService.SetAccountLapseSignal(ctx, accountID, false); err != nil {
		t.Fatalf("set account lapse signal: %v", err)
	}

	if _, err := authService.Authenticate(ctx, session.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected pre-lapse session revoked immediately, got %v", err)
	}
	account, err := store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account after lapse: %v", err)
	}
	if account.PremiumActive {
		t.Fatal("expected premium_active cleared after lapse signal")
	}
	lapsedAt, err := store.GetAccountLapsedAt(ctx, accountID)
	if err != nil {
		t.Fatalf("get account lapsed at: %v", err)
	}
	if lapsedAt == nil || !lapsedAt.Equal(firstLapse) {
		t.Fatalf("expected lapsed_at %s, got %v", firstLapse, lapsedAt)
	}

	// Replay with a later clock reading: idempotent success, marker unmoved.
	bridgeService.now = func() time.Time { return firstLapse.Add(2 * time.Hour) }
	if err := bridgeService.SetAccountLapseSignal(ctx, accountID, false); err != nil {
		t.Fatalf("replay set account lapse signal: %v", err)
	}
	replayedLapsedAt, err := store.GetAccountLapsedAt(ctx, accountID)
	if err != nil {
		t.Fatalf("get account lapsed at after replay: %v", err)
	}
	if replayedLapsedAt == nil || !replayedLapsedAt.Equal(firstLapse) {
		t.Fatalf("expected lapsed_at to stay pinned at %s after replay, got %v", firstLapse, replayedLapsedAt)
	}
}

func TestSetAccountLapseSignalUnknownAccountIsIdempotentNoOp(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	if err := bridgeService.SetAccountLapseSignal(context.Background(), "neverexisted1234", false); err != nil {
		t.Fatalf("expected lapse signal for a never-existed account to succeed, got %v", err)
	}
	if err := bridgeService.SetAccountLapseSignal(context.Background(), "neverexisted1234", true); err != nil {
		t.Fatalf("expected retraction for a never-existed account to succeed, got %v", err)
	}
}

// TestSetAccountLapseSignalRefusesSelfHostedAccount asserts the bridge
// credential can never mark a self-hosted account lapsed, revoke its
// sessions, or touch its premium_active flag, even when handed that
// account's real id — mirroring PurgeManagedAccount's identical refusal.
func TestSetAccountLapseSignalRefusesSelfHostedAccount(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	ctx := context.Background()
	registered, err := authService.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := bridgeService.SetAccountLapseSignal(ctx, registered.AccountID, false); !errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected ErrInvalidManagedAccount for self-hosted account, got %v", err)
	}

	if _, err := authService.Authenticate(ctx, registered.SessionToken); err != nil {
		t.Fatalf("expected self-hosted session to survive refused lapse signal, got %v", err)
	}
	lapsedAt, err := store.GetAccountLapsedAt(ctx, registered.AccountID)
	if err != nil {
		t.Fatalf("get self-hosted account lapsed at: %v", err)
	}
	if lapsedAt != nil {
		t.Fatalf("expected self-hosted account lapsed_at to stay nil, got %v", lapsedAt)
	}
}

// TestSetAccountLapseSignalActiveTrueRetractsWithoutTouchingSessionsOrPremium
// covers the active=true retraction path: it clears a previously recorded
// lapse marker but leaves premium_active and any live session completely
// alone — reactivating premium and issuing a session both stay the mint
// path's exclusive job (CreateManagedSession).
func TestSetAccountLapseSignalActiveTrueRetractsWithoutTouchingSessionsOrPremium(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	ctx := context.Background()
	const accountID = "managedacct1234"

	if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
		t.Fatalf("create managed session: %v", err)
	}
	if err := bridgeService.SetAccountLapseSignal(ctx, accountID, false); err != nil {
		t.Fatalf("lapse account: %v", err)
	}
	if lapsedAt, err := store.GetAccountLapsedAt(ctx, accountID); err != nil || lapsedAt == nil {
		t.Fatalf("expected lapsed_at set before retraction, got %v err=%v", lapsedAt, err)
	}

	// A session minted directly via CreateSessionForAccount (unlike the
	// full managed-bridge mint, this does NOT touch premium_active or
	// lapsed_at — see AuthService.CreateSessionForAccount) exists
	// concurrently with the still-set lapse marker. Retraction must leave it
	// alone: SetAccountLapseSignal(active=true) only ever clears the marker,
	// it never revokes sessions.
	concurrentSession, err := authService.CreateSessionForAccount(ctx, accountID)
	if err != nil {
		t.Fatalf("create concurrent session for account: %v", err)
	}

	if err := bridgeService.SetAccountLapseSignal(ctx, accountID, true); err != nil {
		t.Fatalf("retract lapse signal: %v", err)
	}

	lapsedAt, err := store.GetAccountLapsedAt(ctx, accountID)
	if err != nil {
		t.Fatalf("get account lapsed at after retraction: %v", err)
	}
	if lapsedAt != nil {
		t.Fatalf("expected lapsed_at cleared after retraction, got %v", lapsedAt)
	}
	account, err := store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account after retraction: %v", err)
	}
	if account.PremiumActive {
		t.Fatal("expected premium_active to remain false after retraction — reactivation is the mint path's job")
	}
	if _, err := authService.Authenticate(ctx, concurrentSession.SessionToken); err != nil {
		t.Fatalf("expected the concurrent session to survive retraction untouched, got %v", err)
	}
}

// TestSetAccountLapseSignalMintAfterLapseClearsMarkerAndReenables is the
// resubscribe path: a session mint (CreateManagedSession) after a lapse
// signal must clear lapsed_at and restore premium_active on its own,
// without any explicit active=true retraction call, and the newly minted
// session must authenticate normally.
func TestSetAccountLapseSignalMintAfterLapseClearsMarkerAndReenables(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	ctx := context.Background()
	const accountID = "managedacct1234"

	if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
		t.Fatalf("create managed session: %v", err)
	}
	if err := bridgeService.SetAccountLapseSignal(ctx, accountID, false); err != nil {
		t.Fatalf("lapse account: %v", err)
	}
	if lapsedAt, err := store.GetAccountLapsedAt(ctx, accountID); err != nil || lapsedAt == nil {
		t.Fatalf("expected lapsed_at set before resubscribe mint, got %v err=%v", lapsedAt, err)
	}

	resubscribeSession, err := bridgeService.CreateManagedSession(ctx, accountID)
	if err != nil {
		t.Fatalf("create resubscribe managed session: %v", err)
	}

	lapsedAt, err := store.GetAccountLapsedAt(ctx, accountID)
	if err != nil {
		t.Fatalf("get account lapsed at after resubscribe mint: %v", err)
	}
	if lapsedAt != nil {
		t.Fatalf("expected resubscribe mint to clear lapsed_at, got %v", lapsedAt)
	}
	account, err := store.FindAccountByID(ctx, accountID)
	if err != nil {
		t.Fatalf("find account after resubscribe mint: %v", err)
	}
	if !account.PremiumActive {
		t.Fatal("expected premium_active restored true after resubscribe mint")
	}
	if _, err := authService.Authenticate(ctx, resubscribeSession.SessionToken); err != nil {
		t.Fatalf("expected resubscribe session to authenticate, got %v", err)
	}
}

func TestSetAccountLapseSignalSurfacesAccountLookupStoreError(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err := bridgeService.SetAccountLapseSignal(context.Background(), "managedacct1234", false)
	if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
		t.Fatalf("expected a store error from the account lookup, got %v", err)
	}
}

// TestSetAccountLapseSignalSurfacesWriteStoreErrors drops
// accounts.lapsed_at out from under a live server for the active=false
// (SetAccountLapsed) and active=true (ClearAccountLapse) branches, and drops
// the sessions table for the post-lapse session-revocation branch — three
// distinct store-error paths inside SetAccountLapseSignal, each isolated
// without disturbing the account lookup that must succeed first.
func TestSetAccountLapseSignalSurfacesWriteStoreErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("SetAccountLapsed failure", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		authService := NewAuthService(store, 24*time.Hour)
		bridgeService := NewManagedBridgeService(store, authService)
		const accountID = "managedacct1234"
		if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
			t.Fatalf("create managed session: %v", err)
		}

		dropAccountsLapsedAtColumn(t, dbPath)

		err := bridgeService.SetAccountLapseSignal(ctx, accountID, false)
		if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
			t.Fatalf("expected a store error from SetAccountLapsed, got %v", err)
		}
	})

	t.Run("ClearAccountLapse failure", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		authService := NewAuthService(store, 24*time.Hour)
		bridgeService := NewManagedBridgeService(store, authService)
		const accountID = "managedacct1234"
		if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
			t.Fatalf("create managed session: %v", err)
		}

		dropAccountsLapsedAtColumn(t, dbPath)

		err := bridgeService.SetAccountLapseSignal(ctx, accountID, true)
		if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
			t.Fatalf("expected a store error from ClearAccountLapse, got %v", err)
		}
	})

	t.Run("DeleteAllSessionsForAccount failure", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		authService := NewAuthService(store, 24*time.Hour)
		bridgeService := NewManagedBridgeService(store, authService)
		const accountID = "managedacct1234"
		if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
			t.Fatalf("create managed session: %v", err)
		}

		dropTable(t, dbPath, "sessions")

		err := bridgeService.SetAccountLapseSignal(ctx, accountID, false)
		if err == nil || errors.Is(err, ErrInvalidManagedAccount) {
			t.Fatalf("expected a store error from DeleteAllSessionsForAccount, got %v", err)
		}
	})
}

func TestExistingOrCreatedAtPrefersExistingTimestamp(t *testing.T) {
	now := time.Now().UTC()
	existing := now.Add(-time.Hour)

	if got := existingOrCreatedAt(models.Account{}, now); !got.Equal(now) {
		t.Fatalf("expected fallback timestamp, got %s", got)
	}
	if got := existingOrCreatedAt(models.Account{CreatedAt: existing}, now); !got.Equal(existing) {
		t.Fatalf("expected existing timestamp, got %s", got)
	}
}
