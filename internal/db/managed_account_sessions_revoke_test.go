package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// seedSessionRevokeAccount creates an account at mode with a row in every
// per-account table, two sessions among them, and a recorded lapse (so
// premium_active, lapsed_at and entitlement_signal_as_of all hold
// non-default values a stray write would change).
func seedSessionRevokeAccount(t *testing.T, store *Store, accountID string, mode string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := store.CreateAccount(ctx, models.Account{
		ID:               accountID,
		Login:            accountID + "@example.com",
		PasswordHash:     "hash",
		RecoveryCodeHash: "recovery-hash",
		Mode:             mode,
		PremiumActive:    true,
		CreatedAt:        now,
	}); err != nil {
		t.Fatalf("create account %s: %v", accountID, err)
	}
	if _, err := store.db.ExecContext(ctx,
		`UPDATE accounts SET lapsed_at = ?, entitlement_signal_as_of = ? WHERE id = ?`,
		now.Add(-2*time.Hour).Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano), accountID,
	); err != nil {
		t.Fatalf("record lapse state for %s: %v", accountID, err)
	}

	for _, suffix := range []string{"-a", "-b"} {
		if _, err := store.CreateSession(ctx, models.Session{
			ID:         accountID + "-session" + suffix,
			AccountID:  accountID,
			TokenHash:  accountID + "-token-hash" + suffix,
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  now.Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("create session for %s: %v", accountID, err)
		}
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
	if _, err := store.UpsertEncryptedBlob(ctx, accountID+"-token-hash-a", noGenerationCeiling, models.EncryptedBlob{
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
	if _, _, err := store.ReserveTOTPAttempt(ctx, accountID, now, 15*time.Minute, 10); err != nil {
		t.Fatalf("create totp failure window for %s: %v", accountID, err)
	}
}

// accountStateSnapshot is everything the session revoke must leave alone: the
// account row's lapse state and the row count of every per-account table
// other than sessions.
func accountStateSnapshot(t *testing.T, store *Store, accountID string) map[string]any {
	t.Helper()
	snapshot := map[string]any{}
	var premiumActive int
	var lapsedAt, signalAsOf string
	if err := store.db.QueryRowContext(context.Background(),
		`SELECT premium_active, COALESCE(lapsed_at, ''), COALESCE(entitlement_signal_as_of, '') FROM accounts WHERE id = ?`,
		accountID,
	).Scan(&premiumActive, &lapsedAt, &signalAsOf); err != nil {
		t.Fatalf("read lapse state of %s: %v", accountID, err)
	}
	snapshot["premium_active"] = premiumActive
	snapshot["lapsed_at"] = lapsedAt
	snapshot["entitlement_signal_as_of"] = signalAsOf
	for _, table := range accountChildTables {
		if table == "sessions" {
			continue
		}
		rows := countAccountRows(t, store, table, accountID)
		if rows == 0 {
			t.Fatalf("seed covers no %s row for %s; seed one so the revoke is checked against it", table, accountID)
		}
		snapshot[table] = rows
	}
	return snapshot
}

func assertSnapshotUnchanged(t *testing.T, label string, before map[string]any, after map[string]any) {
	t.Helper()
	for key, want := range before {
		if got := after[key]; got != want {
			t.Fatalf("%s: %s changed from %v to %v", label, key, want, got)
		}
	}
}

func TestDeleteManagedAccountSessionsRevokesOnlyTheManagedAccountsSessions(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	const targetID = "managed-revoke-target"
	const bystanderID = "managed-revoke-bystander"
	const selfHostedID = "self-hosted-managed-shaped-id"
	seedSessionRevokeAccount(t, store, targetID, "managed")
	seedSessionRevokeAccount(t, store, bystanderID, "managed")
	seedSessionRevokeAccount(t, store, selfHostedID, "self_hosted")

	before := map[string]map[string]any{}
	for _, accountID := range []string{targetID, bystanderID, selfHostedID} {
		before[accountID] = accountStateSnapshot(t, store, accountID)
	}

	if err := store.DeleteManagedAccountSessions(ctx, targetID); err != nil {
		t.Fatalf("revoke managed sessions: %v", err)
	}
	if rows := countAccountRows(t, store, "sessions", targetID); rows != 0 {
		t.Fatalf("expected every session of the managed target deleted, found %d", rows)
	}
	if rows := countAccountRows(t, store, "sessions", bystanderID); rows != 2 {
		t.Fatalf("expected the other managed account's 2 sessions intact, found %d", rows)
	}

	// A self-hosted account handed by its own id keeps every session.
	if err := store.DeleteManagedAccountSessions(ctx, selfHostedID); err != nil {
		t.Fatalf("revoke on a self-hosted id: want nil like an absent account, got %v", err)
	}
	if rows := countAccountRows(t, store, "sessions", selfHostedID); rows != 2 {
		t.Fatalf("expected the self-hosted account's 2 sessions intact, found %d", rows)
	}

	// An absent account and a repeat on a managed account with no sessions
	// left are both no-op successes.
	if err := store.DeleteManagedAccountSessions(ctx, "managed-never-existed"); err != nil {
		t.Fatalf("revoke on an absent account: want nil, got %v", err)
	}
	if err := store.DeleteManagedAccountSessions(ctx, targetID); err != nil {
		t.Fatalf("repeat revoke: want nil, got %v", err)
	}

	for _, accountID := range []string{targetID, bystanderID, selfHostedID} {
		assertSnapshotUnchanged(t, accountID, before[accountID], accountStateSnapshot(t, store, accountID))
	}
}

func TestDeleteManagedAccountSessionsSurfacesAStoreFailure(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	dropTable(t, dbPath, "sessions")

	err := store.DeleteManagedAccountSessions(context.Background(), "managed-revoke-target")
	if err == nil || !strings.Contains(err.Error(), "delete managed account sessions") {
		t.Fatalf("expected the wrapped delete error, got %v", err)
	}
}
