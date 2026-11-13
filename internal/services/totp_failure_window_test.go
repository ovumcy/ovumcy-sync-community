package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

const totpWindowTestPassword = "correct horse battery staple"

// wrongTOTPCode returns a code that none of the three steps the skew window
// accepts at now would match, so a "wrong guess" can never land by chance.
func wrongTOTPCode(t *testing.T, secret []byte, now time.Time) string {
	t.Helper()
	step := now.UTC().Unix() / security.TOTPStepSeconds
	valid := map[string]bool{}
	for _, s := range []int64{step - 1, step, step + 1} {
		valid[security.GenerateTOTPCode(secret, s)] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatal("no wrong code candidate left")
	return ""
}

func setTOTPClock(auth *AuthService, totp *TOTPService, now time.Time) {
	auth.now = func() time.Time { return now }
	totp.now = func() time.Time { return now }
}

func loginChallengeID(t *testing.T, auth *AuthService) string {
	t.Helper()
	result, err := auth.Login(context.Background(), "owner@example.com", totpWindowTestPassword)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.TOTPChallenge == nil {
		t.Fatalf("expected a TOTP challenge, got %#v", result)
	}
	return result.TOTPChallenge.ChallengeID
}

// freshChallengeID mints a challenge exactly as Login does once the password
// checks out, without paying a bcrypt compare per cycle.
func freshChallengeID(t *testing.T, totp *TOTPService, accountID string) string {
	t.Helper()
	challengeID, _, err := totp.IssueChallenge(context.Background(), accountID)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	return challengeID
}

// TestReLoginCannotResetTheAccountTOTPBudget is the SYNC-4 proof of concept:
// 20 cycles of a new login challenge + 5 wrong codes. Each challenge carries
// a fresh per-challenge budget, but the account window caps the guesses at
// 10; every later attempt, a correct code after a real login included, is
// locked until the window ends.
func TestReLoginCannotResetTheAccountTOTPBudget(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	loginNow := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, loginNow)
	wrong := wrongTOTPCode(t, secret, loginNow)

	attempt := 0
	for cycle := range 20 {
		challengeID := freshChallengeID(t, totp, accountID)
		for range 5 {
			attempt++
			_, err := totp.VerifyChallenge(ctx, challengeID, wrong)
			if attempt <= maxTOTPAccountFailedAttempts {
				if errors.Is(err, ErrTOTPLocked) {
					t.Fatalf("cycle %d attempt %d: locked before the cap", cycle, attempt)
				}
				continue
			}
			var locked *TOTPLockedError
			if !errors.As(err, &locked) {
				t.Fatalf("cycle %d attempt %d: expected ErrTOTPLocked, got %v", cycle, attempt, err)
			}
			if locked.RetryAfter <= 0 || locked.RetryAfter > TOTPFailureWindow {
				t.Fatalf("attempt %d: RetryAfter %v outside (0, %v]", attempt, locked.RetryAfter, TOTPFailureWindow)
			}
		}
	}

	correct := security.GenerateTOTPCode(secret, loginNow.Unix()/security.TOTPStepSeconds)
	if _, err := totp.VerifyChallenge(ctx, loginChallengeID(t, auth), correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("a correct code inside a spent window must stay locked, got %v", err)
	}
}

// TestAccountTOTPWindowEndsAndSuccessClearsIt pins the window's two exits:
// the window running out, and a successful verify resetting the count.
func TestAccountTOTPWindowEndsAndSuccessClearsIt(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	start := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, start)
	wrong := wrongTOTPCode(t, secret, start)
	for range maxTOTPAccountFailedAttempts {
		challengeID := freshChallengeID(t, totp, accountID)
		if _, err := totp.VerifyChallenge(ctx, challengeID, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode, got %v", err)
		}
	}

	almost := start.Add(TOTPFailureWindow - time.Second)
	setTOTPClock(auth, totp, almost)
	var locked *TOTPLockedError
	if _, err := totp.VerifyChallenge(ctx, freshChallengeID(t, totp, accountID), wrong); !errors.As(err, &locked) {
		t.Fatalf("expected lock one second before the window ends, got %v", err)
	}
	if locked.RetryAfter != time.Second {
		t.Fatalf("RetryAfter = %v, want 1s", locked.RetryAfter)
	}

	after := start.Add(TOTPFailureWindow)
	setTOTPClock(auth, totp, after)
	correct := security.GenerateTOTPCode(secret, after.Unix()/security.TOTPStepSeconds)
	result, err := totp.VerifyChallenge(ctx, loginChallengeID(t, auth), correct)
	if err != nil || result.SessionToken == "" {
		t.Fatalf("expected a session once the window ended, got %#v, %v", result, err)
	}

	// The success cleared the count: a full fresh budget is available.
	later := after.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong = wrongTOTPCode(t, secret, later)
	for i := range maxTOTPAccountFailedAttempts {
		if _, err := totp.VerifyChallenge(ctx, freshChallengeID(t, totp, accountID), wrong); errors.Is(err, ErrTOTPLocked) {
			t.Fatalf("attempt %d after a successful verify: locked, the window was not cleared", i+1)
		}
	}
}

// TestCompletedEnrollmentClearsASpentWindow: a new secret is a fresh guessing
// space, so a window spent before (re-)enrollment must not lock the first
// login with the new secret.
func TestCompletedEnrollmentClearsASpentWindow(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()

	registered, err := auth.Register(ctx, "owner@example.com", totpWindowTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	for range maxTOTPAccountFailedAttempts + 1 {
		if _, _, err := totp.store.ReserveTOTPAttempt(ctx, registered.AccountID, now, TOTPFailureWindow, maxTOTPAccountFailedAttempts); err != nil {
			t.Fatalf("reserve: %v", err)
		}
	}

	start, err := totp.StartEnrollment(ctx, registered.AccountID, totpWindowTestPassword)
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if err := totp.CompleteEnrollment(ctx, registered.AccountID, security.HashToken(registered.SessionToken),
		security.GenerateTOTPCode(secret, now.Unix()/security.TOTPStepSeconds)); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	if _, err := totp.VerifyChallenge(ctx, freshChallengeID(t, totp, registered.AccountID), wrongTOTPCode(t, secret, later)); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("expected a plain wrong-code answer after enrollment, got %v", err)
	}
}

// TestConcurrentDisableGuessesSpendExactlyTheAccountCap: disable has no
// per-challenge budget to burn first, so a concurrent burst drives every
// request into the reservation; exactly the cap get a code check.
func TestConcurrentDisableGuessesSpendExactlyTheAccountCap(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong := wrongTOTPCode(t, secret, later)

	const guesses = 2 * maxTOTPAccountFailedAttempts
	results := make(chan error, guesses)
	var wg sync.WaitGroup
	for range guesses {
		wg.Go(func() {
			results <- totp.Disable(ctx, accountID, totpWindowTestPassword, wrong)
		})
	}
	wg.Wait()
	close(results)

	invalid, locked := 0, 0
	for err := range results {
		switch {
		case errors.Is(err, ErrTOTPInvalidCode):
			invalid++
		case errors.Is(err, ErrTOTPLocked):
			locked++
		default:
			t.Fatalf("unexpected disable result: %v", err)
		}
	}
	if invalid != maxTOTPAccountFailedAttempts || locked != guesses-maxTOTPAccountFailedAttempts {
		t.Fatalf("invalid=%d locked=%d, want %d and %d", invalid, locked, maxTOTPAccountFailedAttempts, guesses-maxTOTPAccountFailedAttempts)
	}
}

// TestDisableSharesTheAccountTOTPWindow: disable checks a code against the
// enrolled secret too, so its wrong guesses spend the same budget and a spent
// window blocks the login challenge as well.
func TestDisableSharesTheAccountTOTPWindow(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong := wrongTOTPCode(t, secret, later)
	for range maxTOTPAccountFailedAttempts {
		if err := totp.Disable(ctx, accountID, totpWindowTestPassword, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode, got %v", err)
		}
	}

	correct := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	if err := totp.Disable(ctx, accountID, totpWindowTestPassword, correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected disable to be locked, got %v", err)
	}
	if _, err := totp.VerifyChallenge(ctx, loginChallengeID(t, auth), correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected the login challenge to share the lock, got %v", err)
	}

	// A wrong password never reaches the code check, so it spends nothing.
	if err := totp.Disable(ctx, accountID, "wrong password entirely", wrong); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
}

func TestVerifyChallengeSurfacesFailureWindowStoreErrors(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	totp := NewTOTPService(store, auth, key, "ovumcy-sync-community-test")
	auth.AttachTOTPChallengeIssuer(totp)
	now := time.Date(2026, 7, 7, 10, 0, 5, 0, time.UTC)
	setTOTPClock(auth, totp, now)
	ctx := context.Background()
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	challengeID := loginChallengeID(t, auth)

	dropTable(t, dbPath, "totp_failure_windows")

	correct := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	if _, err := totp.VerifyChallenge(ctx, challengeID, correct); err == nil || errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected a store error from the challenge path, got %v", err)
	}
	if err := totp.Disable(ctx, accountID, totpWindowTestPassword, correct); err == nil || errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected a store error from disable, got %v", err)
	}
}
