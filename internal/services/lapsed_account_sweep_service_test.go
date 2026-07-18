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
)

const lapsedSweepGracePeriod = 60 * 24 * time.Hour

// seedLapsedCandidateWithFullData provisions a managed account (via the
// bridge mint, matching how a real managed account comes to exist) and fills
// it with a device, a recovery-key package, and an encrypted blob — exactly
// like provisionManagedAccountWithData in internal/api — then records a
// lapse lapsedAgo in the past directly at the store level (bypassing the
// bridge signal, since these tests exercise the sweep in isolation from
// ManagedBridgeService).
func seedLapsedCandidateWithFullData(
	t *testing.T,
	store *db.Store,
	authService *AuthService,
	syncService *SyncService,
	bridgeService *ManagedBridgeService,
	accountID string,
	lapsedAgo time.Duration,
) {
	t.Helper()
	ctx := context.Background()

	if _, err := bridgeService.CreateManagedSession(ctx, accountID); err != nil {
		t.Fatalf("create managed session for %s: %v", accountID, err)
	}
	if _, err := syncService.AttachDevice(ctx, accountID, accountID+"-device", "Test Device"); err != nil {
		t.Fatalf("attach device for %s: %v", accountID, err)
	}
	ciphertext := []byte(accountID + "-ciphertext")
	sum := sha256.Sum256(ciphertext)
	if _, err := syncService.PutBlob(ctx, accountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}); err != nil {
		t.Fatalf("put blob for %s: %v", accountID, err)
	}
	if _, err := syncService.PutRecoveryKeyPackage(ctx, accountID, PutRecoveryKeyPackageInput{
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: strings.Repeat("c", 16),
	}); err != nil {
		t.Fatalf("put recovery key package for %s: %v", accountID, err)
	}

	if err := store.SetAccountLapsed(ctx, accountID, time.Now().UTC().Add(-lapsedAgo)); err != nil {
		t.Fatalf("lapse %s: %v", accountID, err)
	}
}

// TestLapsedAccountSweepServiceDeletesPastGraceSurvivesWithinGraceAndSkipsCommunityAccounts
// is the sweep's core contract in one scenario: a managed account lapsed
// well past the grace period is deleted with EVERY row gone (device, blob,
// recovery-key package, session, account row itself); a managed account
// lapsed inside the grace window is left completely untouched; and a
// self-hosted (community-mode) account — the required regression — is never
// even a candidate and survives untouched, because it structurally can never
// carry a lapsed_at marker (SetAccountLapsed itself refuses non-managed
// accounts; see internal/db's own regression test for that layer).
func TestLapsedAccountSweepServiceDeletesPastGraceSurvivesWithinGraceAndSkipsCommunityAccounts(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	authService := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	bridgeService := NewManagedBridgeService(store, authService)
	sweepService := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod)

	const pastGraceID = "managedpastgrace1"
	const withinGraceID = "managedwithingrac"
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, pastGraceID, 90*24*time.Hour)
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, withinGraceID, 10*24*time.Hour)

	selfHostedRegistered, err := authService.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register self-hosted account: %v", err)
	}
	selfHostedCiphertext := []byte("self-hosted-ciphertext")
	selfHostedSum := sha256.Sum256(selfHostedCiphertext)
	if _, err := syncService.PutBlob(ctx, selfHostedRegistered.AccountID, PutBlobInput{
		SchemaVersion:  1,
		Generation:     1,
		ChecksumSHA256: hex.EncodeToString(selfHostedSum[:]),
		Ciphertext:     selfHostedCiphertext,
	}); err != nil {
		t.Fatalf("put self-hosted blob: %v", err)
	}

	result, err := sweepService.Run(ctx, 0, false)
	if err != nil {
		t.Fatalf("run sweep: %v", err)
	}
	if result.Examined != 1 {
		t.Fatalf("expected exactly 1 candidate examined (only the past-grace account), got %d", result.Examined)
	}
	if result.Deleted != 1 || len(result.DeletedAccountIDs) != 1 || result.DeletedAccountIDs[0] != pastGraceID {
		t.Fatalf("expected only %q deleted, got %#v", pastGraceID, result)
	}

	// Past-grace: every row gone.
	if _, err := store.FindAccountByID(ctx, pastGraceID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected past-grace account row gone, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, pastGraceID); err != ErrBlobNotFound {
		t.Fatalf("expected past-grace blob gone, got %v", err)
	}
	if _, err := syncService.GetRecoveryKeyPackage(ctx, pastGraceID); err != ErrRecoveryPackageNotFound {
		t.Fatalf("expected past-grace recovery key package gone, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, pastGraceID); err != nil || count != 0 {
		t.Fatalf("expected zero past-grace devices, got count=%d err=%v", count, err)
	}

	// Within-grace: untouched.
	if _, err := store.FindAccountByID(ctx, withinGraceID); err != nil {
		t.Fatalf("expected within-grace account to survive, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, withinGraceID); err != nil {
		t.Fatalf("expected within-grace blob to survive, got %v", err)
	}

	// Self-hosted: untouched (the regression).
	if _, err := store.FindAccountByID(ctx, selfHostedRegistered.AccountID); err != nil {
		t.Fatalf("expected self-hosted account to survive, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, selfHostedRegistered.AccountID); err != nil {
		t.Fatalf("expected self-hosted blob to survive, got %v", err)
	}
}

func TestLapsedAccountSweepServiceDryRunReportsWithoutDeleting(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	authService := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	bridgeService := NewManagedBridgeService(store, authService)
	sweepService := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod)

	const accountID = "manageddryrun0001"
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, accountID, 90*24*time.Hour)

	result, err := sweepService.Run(ctx, 0, true)
	if err != nil {
		t.Fatalf("run dry-run sweep: %v", err)
	}
	if result.Examined != 1 {
		t.Fatalf("expected 1 examined in dry-run, got %d", result.Examined)
	}
	if result.Deleted != 0 || len(result.DeletedAccountIDs) != 0 {
		t.Fatalf("expected nothing deleted in dry-run, got %#v", result)
	}

	if _, err := store.FindAccountByID(ctx, accountID); err != nil {
		t.Fatalf("expected account to survive a dry-run, got %v", err)
	}
}

func TestLapsedAccountSweepServiceRespectsLimit(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	authService := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	bridgeService := NewManagedBridgeService(store, authService)
	sweepService := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod)

	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, "managedlimittest1", 90*24*time.Hour)
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, "managedlimittest2", 91*24*time.Hour)

	result, err := sweepService.Run(ctx, 1, false)
	if err != nil {
		t.Fatalf("run limited sweep: %v", err)
	}
	if result.Examined != 1 || result.Deleted != 1 {
		t.Fatalf("expected exactly 1 examined and deleted with limit=1, got %#v", result)
	}
}

// TestLapsedAccountSweepServiceContinuesPastPerCandidateDeleteErrorsAndJoinsThem
// proves Run does not abort the whole batch when a candidate's delete fails
// for an infrastructure reason (as opposed to the benign "no longer
// eligible" ErrNotFound): every candidate is still examined, none are
// deleted, and the errors are aggregated via errors.Join rather than only
// the first one being surfaced.
func TestLapsedAccountSweepServiceContinuesPastPerCandidateDeleteErrorsAndJoinsThem(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	ctx := context.Background()

	authService := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	bridgeService := NewManagedBridgeService(store, authService)
	sweepService := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod)

	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, "managederrjoina01", 90*24*time.Hour)
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, "managederrjoinb01", 91*24*time.Hour)

	// Dropping a child table breaks DeleteLapsedManagedAccount's transaction
	// for EVERY candidate identically (its child-table loop touches
	// "sessions" unconditionally) — this is a real infrastructure fault
	// that must not stop the sweep from attempting the rest of the batch.
	dropTable(t, dbPath, "sessions")

	result, err := sweepService.Run(ctx, 0, false)
	if err == nil {
		t.Fatal("expected the sweep to report an aggregated error")
	}
	if result.Examined != 2 {
		t.Fatalf("expected both candidates examined despite the first failing, got %d", result.Examined)
	}
	if result.Deleted != 0 || len(result.DeletedAccountIDs) != 0 {
		t.Fatalf("expected nothing deleted when every delete fails, got %#v", result)
	}
	if strings.Count(err.Error(), "delete lapsed account") < 2 {
		t.Fatalf("expected errors.Join to aggregate both candidates' failures, got %v", err)
	}
}

func TestLapsedAccountSweepServiceListFailureAbortsImmediately(t *testing.T) {
	store := openTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	sweepService := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod)

	result, err := sweepService.Run(context.Background(), 0, false)
	if err == nil || !strings.Contains(err.Error(), "list lapsed account candidates") {
		t.Fatalf("expected a wrapped listing error, got %v", err)
	}
	if result.Examined != 0 || result.Deleted != 0 || result.DeletedAccountIDs != nil {
		t.Fatalf("expected an empty result on listing failure, got %#v", result)
	}
}

// TestLapsedAccountSweepServiceCutoffIsFixedForTheWholeRun asserts Run
// computes its cutoff once from now()-gracePeriod and reuses that exact
// value for both the candidate listing and the delete-time re-check,
// matching the doc comment's "never spuriously excludes a candidate purely
// because wall-clock time advanced during the run" claim. Overriding now to
// return a fixed instant and asserting the account lapsed exactly
// gracePeriod-1-second ago survives while gracePeriod+1-second ago is deleted
// pins the boundary precisely.
func TestLapsedAccountSweepServiceCutoffIsFixedForTheWholeRun(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	authService := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	bridgeService := NewManagedBridgeService(store, authService)
	sweepService := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod)

	fixedNow := time.Now().UTC()
	sweepService.now = func() time.Time { return fixedNow }

	const justInsideID = "managedjustinside"
	const justOutsideID = "managedjustoutsid"
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, justInsideID, lapsedSweepGracePeriod-time.Second)
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, justOutsideID, lapsedSweepGracePeriod+time.Second)

	result, err := sweepService.Run(ctx, 0, false)
	if err != nil {
		t.Fatalf("run sweep: %v", err)
	}
	if result.Deleted != 1 || result.DeletedAccountIDs[0] != justOutsideID {
		t.Fatalf("expected only the just-outside-grace account deleted, got %#v", result)
	}
	if _, err := store.FindAccountByID(ctx, justInsideID); err != nil {
		t.Fatalf("expected the just-inside-grace account to survive, got %v", err)
	}
}

// mintRacingSweepStore wraps the real store and stages the resubscribe race
// the sweep must tolerate: a session mint landing between the sweep's
// candidate listing and its per-candidate delete. Before delegating each
// delete it clears the account's lapse marker exactly the way a real mint
// does (lapsed_at = NULL), so the REAL DeleteLapsedManagedAccount's
// in-transaction re-check sees an un-lapsed account and refuses with
// db.ErrNotFound — nothing about the refusal itself is faked.
type mintRacingSweepStore struct {
	inner *db.Store
	t     *testing.T
}

func (s *mintRacingSweepStore) ListLapsedManagedAccountIDs(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	return s.inner.ListLapsedManagedAccountIDs(ctx, cutoff, limit)
}

func (s *mintRacingSweepStore) DeleteLapsedManagedAccount(ctx context.Context, accountID string, cutoff time.Time) error {
	s.t.Helper()
	if err := s.inner.ClearAccountLapse(ctx, accountID); err != nil {
		s.t.Fatalf("clear lapse to stage the racing mint: %v", err)
	}
	return s.inner.DeleteLapsedManagedAccount(ctx, accountID, cutoff)
}

// TestLapsedAccountSweepServiceTreatsMintRacedCandidateAsBenignSkip proves
// the sweep treats a candidate whose lapse marker vanished between listing
// and delete (a resubscribe mint racing the sweep) as the benign, by-design
// skip it is: examined but not deleted, no error reported, and the account
// plus every row it owns survive completely intact.
func TestLapsedAccountSweepServiceTreatsMintRacedCandidateAsBenignSkip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	authService := NewAuthService(store, 24*time.Hour)
	syncService := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	bridgeService := NewManagedBridgeService(store, authService)
	sweepService := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod)

	const racedID = "managedracedmint1"
	seedLapsedCandidateWithFullData(t, store, authService, syncService, bridgeService, racedID, 90*24*time.Hour)

	sweepService.store = &mintRacingSweepStore{inner: store, t: t}

	result, err := sweepService.Run(ctx, 0, false)
	if err != nil {
		t.Fatalf("expected the raced candidate to be a benign skip, got error %v", err)
	}
	if result.Examined != 1 {
		t.Fatalf("expected the raced candidate to be examined, got %d", result.Examined)
	}
	if result.Deleted != 0 || len(result.DeletedAccountIDs) != 0 {
		t.Fatalf("expected nothing deleted when a mint raced the sweep, got %#v", result)
	}

	if _, err := store.FindAccountByID(ctx, racedID); err != nil {
		t.Fatalf("expected the raced account row to survive, got %v", err)
	}
	if _, err := syncService.GetBlob(ctx, racedID); err != nil {
		t.Fatalf("expected the raced account's blob to survive, got %v", err)
	}
	if _, err := syncService.GetRecoveryKeyPackage(ctx, racedID); err != nil {
		t.Fatalf("expected the raced account's recovery key package to survive, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, racedID); err != nil || count != 1 {
		t.Fatalf("expected the raced account's device to survive, got count=%d err=%v", count, err)
	}
}
