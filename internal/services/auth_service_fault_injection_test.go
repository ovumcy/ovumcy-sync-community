package services

// Fault-injection and edge-case coverage for internal/services/auth_service.go
// (residual coverage debt: the internal/db and internal/services fault-injection
// idioms — openFileBackedTestStore + dropTable, established for the db package
// in internal/db/fault_injection_test.go — had never been applied to
// AuthService's own methods). No production code changes; every technique
// here matches an existing precedent elsewhere in the suite (closed-store,
// dropped table, and raw-row corruption via a second connection).

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// TestRegisterRejectsPasswordOverBcryptByteLimit exercises Register's
// HashPassword generic (non-ErrWeakPassword) branch: Register only enforces
// HashPassword's own 12-rune minimum, so a long-but-otherwise-valid password
// can still trip bcrypt's own 72-byte ceiling — the same edge case
// TestHashPasswordRejectsPasswordOverBcryptByteLimit exercises directly in
// internal/security, reached here through the service.
func TestRegisterRejectsPasswordOverBcryptByteLimit(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	_, err := service.Register(context.Background(), "owner@example.com", strings.Repeat("a", 100))
	if err == nil {
		t.Fatal("expected Register to fail for a 100-byte password")
	}
	if errors.Is(err, ErrInvalidRegistrationInput) {
		t.Fatalf("expected the raw bcrypt error (not the weak-password mapping), got %v", err)
	}
}

// TestRegisterSurfacesCreateSessionStoreError exercises createSession's
// store.CreateSession generic-error branch AND Register's own wrapper around
// it in one shot: CreateAccount (the earlier call, on "accounts") succeeds
// since only "sessions" is dropped, so Register reaches createSession before
// failing.
func TestRegisterSurfacesCreateSessionStoreError(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	dropTable(t, dbPath, "sessions")

	_, err := service.Register(context.Background(), "owner@example.com", "correct horse battery staple")
	if err == nil {
		t.Fatal("expected Register to fail when the sessions table is dropped")
	}
	if !strings.Contains(err.Error(), "insert session") {
		t.Fatalf("expected the session-creation store error to surface, got %v", err)
	}
}

// TestLoginSurfacesTOTPChallengeIssueStoreError exercises IssueChallenge's
// DeleteTOTPChallengesForAccount error AND Login's own wrapper around
// IssueChallenge's returned error in one shot.
func TestLoginSurfacesTOTPChallengeIssueStoreError(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp := NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)

	ctx := context.Background()
	const password = "correct horse battery staple"
	registered, err := auth.Register(ctx, "owner@example.com", password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	start, err := totp.StartEnrollment(ctx, registered.AccountID, password)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	step := time.Now().UTC().Unix() / security.TOTPStepSeconds
	code := security.GenerateTOTPCode(secret, step)
	if err := totp.CompleteEnrollment(ctx, registered.AccountID, security.HashToken(registered.SessionToken), code); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	dropTable(t, dbPath, "totp_challenges")

	_, err = auth.Login(ctx, "owner@example.com", password)
	if err == nil {
		t.Fatal("expected Login to fail when the totp_challenges table is dropped")
	}
	if !strings.Contains(err.Error(), "delete totp challenges for account") {
		t.Fatalf("expected the challenge-issuance store error to surface, got %v", err)
	}
}

// TestAuthenticateSurfacesFindSessionStoreError exercises
// FindSessionByTokenHash's generic (non-ErrNotFound) branch: it is
// Authenticate's first store call, so closing the store faults it directly.
func TestAuthenticateSurfacesFindSessionStoreError(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	_, err := service.Authenticate(context.Background(), "any-session-token")
	if err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected a store-failure error, not ErrUnauthorized, got %v", err)
	}
}

// TestAuthenticateAccountLookupEdgeCases covers the two FindAccountByID
// branches inside Authenticate, both deterministic static preconditions
// (not races): a session whose account row was deleted out from under it
// (ErrNotFound -> ErrUnauthorized), and a generic store failure once the
// accounts table itself is gone. FindSessionByTokenHash's SELECT and
// TouchSession's UPDATE (neither touches the accounts table or any FK
// column) both keep succeeding in either case — confirmed empirically:
// database/sql only defers a genuine "no such table" error to
// row.Scan()/rows.Next() for the table actually named in the query.
func TestAuthenticateAccountLookupEdgeCases(t *testing.T) {
	t.Run("account row deleted after the session was created", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		ctx := context.Background()

		result, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
		if err != nil {
			t.Fatalf("register: %v", err)
		}

		raw, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open raw sqlite: %v", err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
			t.Fatalf("configure raw sqlite: %v", err)
		}
		// A raw connection has foreign_keys enforcement off by default, so
		// this delete does not cascade to the still-active session row — a
		// deterministic orphan, not a timing-dependent race.
		if _, err := raw.Exec(`DELETE FROM accounts WHERE id = ?`, result.AccountID); err != nil {
			t.Fatalf("orphan the session by deleting its account row: %v", err)
		}

		if _, err := service.Authenticate(ctx, result.SessionToken); err != ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized for an orphaned session, got %v", err)
		}
	})

	t.Run("accounts table dropped after the session was created", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		ctx := context.Background()

		result, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
		if err != nil {
			t.Fatalf("register: %v", err)
		}

		dropTable(t, dbPath, "accounts")

		_, err = service.Authenticate(ctx, result.SessionToken)
		if err == nil || errors.Is(err, ErrUnauthorized) {
			t.Fatalf("expected a store-failure error, not ErrUnauthorized, got %v", err)
		}
	})
}

// TestChangePasswordStoreErrors exercises ChangePassword's remaining
// store-error branches: FindAccountByID's generic error (its first store
// call, isolated with a closed store), the too-long-new-password edge of
// HashPassword's generic branch, and the two account-scoped cleanup deletes
// (different tables, isolated with their own dropped table each).
func TestChangePasswordStoreErrors(t *testing.T) {
	t.Run("closed store fails the account lookup", func(t *testing.T) {
		store := openTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}

		err := service.ChangePassword(context.Background(), "any-account", "any-hash", "any-password", "any-new-password")
		if err == nil || errors.Is(err, ErrUnauthorized) {
			t.Fatalf("expected a store-failure error, not ErrUnauthorized, got %v", err)
		}
	})

	t.Run("new password over the bcrypt byte limit", func(t *testing.T) {
		store := openTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		ctx := context.Background()
		const password = "correct horse battery staple"

		result, err := service.Register(ctx, "owner@example.com", password)
		if err != nil {
			t.Fatalf("register: %v", err)
		}

		err = service.ChangePassword(ctx, result.AccountID, "any-hash", password, strings.Repeat("b", 100))
		if err == nil || errors.Is(err, ErrWeakNewPassword) {
			t.Fatalf("expected the raw bcrypt error, not ErrWeakNewPassword, got %v", err)
		}
	})

	t.Run("sessions table dropped fails session revocation", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		ctx := context.Background()
		const password = "correct horse battery staple"

		result, err := service.Register(ctx, "owner@example.com", password)
		if err != nil {
			t.Fatalf("register: %v", err)
		}

		dropTable(t, dbPath, "sessions")

		err = service.ChangePassword(ctx, result.AccountID, "any-hash", password, "a brand new password")
		if err == nil {
			t.Fatal("expected ChangePassword to fail when the sessions table is dropped")
		}
		if !strings.Contains(err.Error(), "delete other sessions") {
			t.Fatalf("expected the session-revocation store error to surface, got %v", err)
		}
	})

	t.Run("password_reset_tokens table dropped fails reset-token cleanup", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		ctx := context.Background()
		const password = "correct horse battery staple"

		result, err := service.Register(ctx, "owner@example.com", password)
		if err != nil {
			t.Fatalf("register: %v", err)
		}

		dropTable(t, dbPath, "password_reset_tokens")

		err = service.ChangePassword(ctx, result.AccountID, "any-hash", password, "a brand new password")
		if err == nil {
			t.Fatal("expected ChangePassword to fail when the password_reset_tokens table is dropped")
		}
		if !strings.Contains(err.Error(), "delete password reset tokens") {
			t.Fatalf("expected the reset-token cleanup store error to surface, got %v", err)
		}
	})
}

// TestForgotPasswordStoreErrors exercises ForgotPassword's two remaining
// store-error branches: FindAccountByLogin's generic error (its first store
// call) and UpsertPasswordResetToken's generic error (a different table,
// dropped alone).
func TestForgotPasswordStoreErrors(t *testing.T) {
	t.Run("closed store fails the account lookup", func(t *testing.T) {
		store := openTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}

		_, err := service.ForgotPassword(context.Background(), "owner@example.com", "any-recovery-code")
		if err == nil || errors.Is(err, ErrInvalidRecoveryCredentials) {
			t.Fatalf("expected a store-failure error, not ErrInvalidRecoveryCredentials, got %v", err)
		}
	})

	t.Run("password_reset_tokens table dropped fails the upsert", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		ctx := context.Background()

		result, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
		if err != nil {
			t.Fatalf("register: %v", err)
		}

		dropTable(t, dbPath, "password_reset_tokens")

		_, err = service.ForgotPassword(ctx, "owner@example.com", result.RecoveryCode)
		if err == nil {
			t.Fatal("expected ForgotPassword to fail when the password_reset_tokens table is dropped")
		}
		if !strings.Contains(err.Error(), "upsert password reset token") {
			t.Fatalf("expected the reset-token upsert store error to surface, got %v", err)
		}
	})
}

// TestResetPasswordRejectsEmptyToken is a trivial, pure-logic case: an
// empty/whitespace-only reset token must be rejected before any store call.
func TestResetPasswordRejectsEmptyToken(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	if _, err := service.ResetPassword(context.Background(), "   ", "a brand new password"); err != ErrInvalidResetToken {
		t.Fatalf("expected ErrInvalidResetToken for an empty token, got %v", err)
	}
}

// TestResetPasswordSurfacesConsumeTokenStoreError exercises
// ConsumePasswordResetToken's generic (non-ErrNotFound) branch: it is
// ResetPassword's first store call after the trivial empty-token check, so
// closing the store faults it directly.
func TestResetPasswordSurfacesConsumeTokenStoreError(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	_, err := service.ResetPassword(context.Background(), "any-reset-token", "a brand new password")
	if err == nil || errors.Is(err, ErrInvalidResetToken) {
		t.Fatalf("expected a store-failure error, not ErrInvalidResetToken, got %v", err)
	}
}

// TestResetPasswordRejectsPasswordOverBcryptByteLimit exercises
// ResetPassword's HashPassword generic (non-ErrWeakPassword) branch, mirroring
// TestChangePasswordStoreErrors' identical edge case for the password-change
// path.
func TestResetPasswordRejectsPasswordOverBcryptByteLimit(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	ctx := context.Background()

	registered, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registered.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}

	_, err = service.ResetPassword(ctx, forgot.ResetToken, strings.Repeat("c", 100))
	if err == nil || errors.Is(err, ErrWeakNewPassword) {
		t.Fatalf("expected the raw bcrypt error, not ErrWeakNewPassword, got %v", err)
	}
}

// resetPasswordFixture registers an account, issues a forgot-password reset
// token for it, and returns everything a ResetPassword fault-injection test
// needs to reach the account-write steps.
func resetPasswordFixture(t *testing.T, service *AuthService) (accountID, resetToken string) {
	t.Helper()
	ctx := context.Background()

	registered, err := service.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	forgot, err := service.ForgotPassword(ctx, "owner@example.com", registered.RecoveryCode)
	if err != nil {
		t.Fatalf("forgot password: %v", err)
	}
	return registered.AccountID, forgot.ResetToken
}

// TestResetPasswordAccountUpdateEdgeCases covers ResetPassword's
// UpdateAccountPasswordAndRecoveryHash branches: a token whose account row
// was deleted after issuance (ErrNotFound -> ErrInvalidResetToken, a
// deterministic static precondition, not a race — the token lookup and the
// account write are different tables), and a generic store failure once the
// accounts table itself is gone (dropped before ResetPassword is ever
// called, leaving password_reset_tokens untouched so the token consume
// step — this function's actual first store call — still succeeds).
func TestResetPasswordAccountUpdateEdgeCases(t *testing.T) {
	t.Run("account row deleted after the reset token was issued", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		accountID, resetToken := resetPasswordFixture(t, service)

		raw, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open raw sqlite: %v", err)
		}
		t.Cleanup(func() { _ = raw.Close() })
		if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
			t.Fatalf("configure raw sqlite: %v", err)
		}
		if _, err := raw.Exec(`DELETE FROM accounts WHERE id = ?`, accountID); err != nil {
			t.Fatalf("orphan the reset token by deleting its account row: %v", err)
		}

		if _, err := service.ResetPassword(context.Background(), resetToken, "a brand new password"); err != ErrInvalidResetToken {
			t.Fatalf("expected ErrInvalidResetToken for an orphaned reset token, got %v", err)
		}
	})

	t.Run("accounts table dropped before the call", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		_, resetToken := resetPasswordFixture(t, service)

		dropTable(t, dbPath, "accounts")

		_, err := service.ResetPassword(context.Background(), resetToken, "a brand new password")
		if err == nil || errors.Is(err, ErrInvalidResetToken) {
			t.Fatalf("expected a store-failure error, not ErrInvalidResetToken, got %v", err)
		}
		if !strings.Contains(err.Error(), "update account password and recovery") {
			t.Fatalf("expected the account-update store error to surface, got %v", err)
		}
	})
}

// TestResetPasswordCleanupStoreErrors exercises ResetPassword's two
// account-scoped cleanup deletes that run after the account write succeeds:
// DeleteTOTPChallengesForAccount and DeleteAllSessionsForAccount. Each is a
// different table from the account write and from each other, so dropping
// one alone isolates exactly that step.
func TestResetPasswordCleanupStoreErrors(t *testing.T) {
	t.Run("totp_challenges table dropped", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		_, resetToken := resetPasswordFixture(t, service)

		dropTable(t, dbPath, "totp_challenges")

		_, err := service.ResetPassword(context.Background(), resetToken, "a brand new password")
		if err == nil {
			t.Fatal("expected ResetPassword to fail when the totp_challenges table is dropped")
		}
		if !strings.Contains(err.Error(), "delete totp challenges for account") {
			t.Fatalf("expected the challenge-cleanup store error to surface, got %v", err)
		}
	})

	t.Run("sessions table dropped", func(t *testing.T) {
		store, dbPath := openFileBackedTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		_, resetToken := resetPasswordFixture(t, service)

		dropTable(t, dbPath, "sessions")

		_, err := service.ResetPassword(context.Background(), resetToken, "a brand new password")
		if err == nil {
			t.Fatal("expected ResetPassword to fail when the sessions table is dropped")
		}
		if !strings.Contains(err.Error(), "delete all sessions") {
			t.Fatalf("expected the session-cleanup store error to surface, got %v", err)
		}
	})
}

// TestRegenerateRecoveryCodeStoreErrors covers the trivial unknown-account
// case (no test elsewhere exercises it) and the generic account-lookup
// store error (its first store call, isolated with a closed store).
func TestRegenerateRecoveryCodeStoreErrors(t *testing.T) {
	t.Run("unknown account", func(t *testing.T) {
		store := openTestStore(t)
		service := NewAuthService(store, 24*time.Hour)

		if _, err := service.RegenerateRecoveryCode(context.Background(), "missing-account", "any-password"); err != ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized for an unknown account, got %v", err)
		}
	})

	t.Run("closed store fails the account lookup", func(t *testing.T) {
		store := openTestStore(t)
		service := NewAuthService(store, 24*time.Hour)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}

		_, err := service.RegenerateRecoveryCode(context.Background(), "any-account", "any-password")
		if err == nil || errors.Is(err, ErrUnauthorized) {
			t.Fatalf("expected a store-failure error, not ErrUnauthorized, got %v", err)
		}
	})
}

// TestRevokeSessionSurfacesStoreError exercises RevokeSession's generic
// (non-ErrNotFound) branch: DeleteSessionByTokenHash is the only store call
// this method makes, so dropping the sessions table faults it directly.
func TestRevokeSessionSurfacesStoreError(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	dropTable(t, dbPath, "sessions")

	err := service.RevokeSession(context.Background(), "any-session-token")
	if err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected a store-failure error, not ErrUnauthorized, got %v", err)
	}
}

// TestCreateSessionForAccountSurfacesStoreError exercises
// CreateSessionForAccount's FindAccountByID generic-error branch (distinct
// from the existing TestAuthServiceCreateSessionForMissingAccountIsUnauthorized,
// which only reaches the trivial ErrNotFound case).
func TestCreateSessionForAccountSurfacesStoreError(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	_, err := service.CreateSessionForAccount(context.Background(), "any-account")
	if err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected a store-failure error, not ErrUnauthorized, got %v", err)
	}
}
