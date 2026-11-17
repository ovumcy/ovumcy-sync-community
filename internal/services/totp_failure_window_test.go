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

func fromClient(client string) context.Context {
	return WithClientKey(context.Background(), client)
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

func spendSignInBudget(t *testing.T, totp *TOTPService, ctx context.Context, accountID string, wrong string, n int) {
	t.Helper()
	for i := range n {
		if _, err := totp.VerifyChallenge(ctx, freshChallengeID(t, totp, accountID), wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("sign-in guess %d: expected ErrTOTPInvalidCode, got %v", i+1, err)
		}
	}
}

// TestReLoginCannotResetTheSignInTOTPBudget is the SYNC-4 proof of concept:
// 20 cycles of a new login challenge + 5 wrong codes. Each challenge carries
// a fresh per-challenge budget, but the sign-in budget caps the guesses at
// maxTOTPAttempts; every later attempt, a correct code after a real login
// included, is locked until the window ends.
func TestReLoginCannotResetTheSignInTOTPBudget(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := fromClient("203.0.113.7")
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
			if attempt <= maxTOTPAttempts {
				if errors.Is(err, ErrTOTPLocked) {
					t.Fatalf("cycle %d attempt %d: locked before the cap", cycle, attempt)
				}
				continue
			}
			var locked *TOTPLockedError
			if !errors.As(err, &locked) {
				t.Fatalf("cycle %d attempt %d: expected ErrTOTPLocked, got %v", cycle, attempt, err)
			}
			if locked.Error() != ErrTOTPLocked.Error() {
				t.Fatalf("locked error text = %q, want %q", locked.Error(), ErrTOTPLocked.Error())
			}
			if locked.RetryAfter <= 0 || locked.RetryAfter > TOTPAttemptWindow {
				t.Fatalf("attempt %d: RetryAfter %v outside (0, %v]", attempt, locked.RetryAfter, TOTPAttemptWindow)
			}
		}
	}

	correct := security.GenerateTOTPCode(secret, loginNow.Unix()/security.TOTPStepSeconds)
	if _, err := totp.VerifyChallenge(ctx, loginChallengeID(t, auth), correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("a correct code inside a spent budget must stay locked, got %v", err)
	}
}

// TestSignInTOTPBudgetIsKeyedByClientAndAccount: a spent account bucket locks
// every client out of that account's sign-in step, and a spent client bucket
// locks that client out of every account; the window ending opens both.
func TestSignInTOTPBudgetIsKeyedByClientAndAccount(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)
	other, err := auth.Register(context.Background(), "other@example.com", totpWindowTestPassword)
	if err != nil {
		t.Fatalf("register other: %v", err)
	}

	start := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, start)
	wrong := wrongTOTPCode(t, secret, start)
	spendSignInBudget(t, totp, fromClient("203.0.113.7"), accountID, wrong, maxTOTPAttempts)

	if _, err := totp.VerifyChallenge(fromClient("198.51.100.9"), freshChallengeID(t, totp, accountID), wrong); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("another client against the spent account: expected ErrTOTPLocked, got %v", err)
	}
	if _, _, ok := totp.attempts.reserve([]string{
		string(totpPurposeSignIn) + ":client:203.0.113.7",
		string(totpPurposeSignIn) + ":account:" + other.AccountID,
	}, start); ok {
		t.Fatal("the spent client must be refused against another account too")
	}

	almost := start.Add(TOTPAttemptWindow - time.Second)
	setTOTPClock(auth, totp, almost)
	var locked *TOTPLockedError
	if _, err := totp.VerifyChallenge(fromClient("203.0.113.7"), freshChallengeID(t, totp, accountID), wrong); !errors.As(err, &locked) {
		t.Fatalf("expected lock one second before the window ends, got %v", err)
	}
	if locked.RetryAfter != time.Second {
		t.Fatalf("RetryAfter = %v, want 1s", locked.RetryAfter)
	}

	after := start.Add(TOTPAttemptWindow)
	setTOTPClock(auth, totp, after)
	correct := security.GenerateTOTPCode(secret, after.Unix()/security.TOTPStepSeconds)
	result, err := totp.VerifyChallenge(fromClient("203.0.113.7"), loginChallengeID(t, auth), correct)
	if err != nil || result.SessionToken == "" {
		t.Fatalf("expected a session once the window ended, got %#v, %v", result, err)
	}
}

// TestSignInSuccessResetsOnlyTheClientBucket: the owner's own sign-in forgives
// only the owner's client; the account bucket keeps what every other client
// spent against the account, so the success does not hand an attacker a
// fresh budget.
func TestSignInSuccessResetsOnlyTheClientBucket(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	start := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, start)
	wrong := wrongTOTPCode(t, secret, start)
	spendSignInBudget(t, totp, fromClient("203.0.113.7"), accountID, wrong, maxTOTPAttempts-1)

	owner := fromClient("198.51.100.9")
	correct := security.GenerateTOTPCode(secret, start.Unix()/security.TOTPStepSeconds)
	if _, err := totp.VerifyChallenge(owner, loginChallengeID(t, auth), correct); err != nil {
		t.Fatalf("owner sign-in: %v", err)
	}

	// The success was not counted, and the attacker's failures still are:
	// one more guess from anywhere spends the account bucket.
	later := start.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong = wrongTOTPCode(t, secret, later)
	spendSignInBudget(t, totp, fromClient("192.0.2.4"), accountID, wrong, 1)
	if _, err := totp.VerifyChallenge(owner, freshChallengeID(t, totp, accountID), wrong); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected the account bucket to keep the other clients' failures, got %v", err)
	}
}

// TestSpentSignInBudgetLeavesInSessionStepUpsReachable is the lock-out the
// budgets close: a password holder without a session spends the sign-in
// budget, and the owner's session can still change the password, rotate the
// recovery code and disable TOTP with a correct code.
func TestSpentSignInBudgetLeavesInSessionStepUpsReachable(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, sessionToken, secret, _ := enrollTOTP(t, auth, totp, now)
	sessionHash := security.HashToken(sessionToken)

	start := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, start)
	attacker := fromClient("203.0.113.7")
	spendSignInBudget(t, totp, attacker, accountID, wrongTOTPCode(t, secret, start), maxTOTPAttempts)

	owner := fromClient("198.51.100.9")
	codeAt := func(at time.Time) string {
		setTOTPClock(auth, totp, at)
		return security.GenerateTOTPCode(secret, at.Unix()/security.TOTPStepSeconds)
	}
	if _, err := auth.RegenerateRecoveryCode(owner, accountID, StepUp{SessionTokenHash: sessionHash, CurrentPassword: totpWindowTestPassword}, codeAt(start)); err != nil {
		t.Fatalf("regenerate with a spent sign-in budget: %v", err)
	}
	next := start.Add(security.TOTPStepSeconds * time.Second)
	if err := totp.Disable(owner, accountID, StepUp{SessionTokenHash: sessionHash, CurrentPassword: totpWindowTestPassword, TOTPCode: codeAt(next)}); err != nil {
		t.Fatalf("disable with a spent sign-in budget: %v", err)
	}
}

// TestSpentStepUpBudgetLeavesSignInReachable: a stolen session that spends
// the step-up budget does not lock the owner's sign-in.
func TestSpentStepUpBudgetLeavesSignInReachable(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, sessionToken, secret, _ := enrollTOTP(t, auth, totp, now)

	start := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, start)
	thief := fromClient("203.0.113.7")
	wrong := wrongTOTPCode(t, secret, start)
	for range maxTOTPAttempts {
		if _, err := auth.RegenerateRecoveryCode(thief, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode, got %v", err)
		}
	}

	correct := security.GenerateTOTPCode(secret, start.Unix()/security.TOTPStepSeconds)
	if _, err := totp.VerifyChallenge(fromClient("203.0.113.7"), loginChallengeID(t, auth), correct); err != nil {
		t.Fatalf("sign-in with a spent step-up budget: %v", err)
	}
}

// TestStepUpSuccessResetsBothBuckets: an in-session success clears the
// client and the account bucket, so the owner's typos never accumulate into
// a lock-out of their own settings.
func TestStepUpSuccessResetsBothBuckets(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, sessionToken, secret, _ := enrollTOTP(t, auth, totp, now)
	ctx := fromClient("198.51.100.9")
	regen := func(code string) error {
		_, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}, code)
		return err
	}

	start := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, start)
	wrong := wrongTOTPCode(t, secret, start)
	for range maxTOTPAttempts - 1 {
		if err := regen(wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode, got %v", err)
		}
	}
	if err := regen(security.GenerateTOTPCode(secret, start.Unix()/security.TOTPStepSeconds)); err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	later := start.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong = wrongTOTPCode(t, secret, later)
	for i := range maxTOTPAttempts {
		if err := regen(wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("guess %d after a success: expected a full fresh budget, got %v", i+1, err)
		}
	}
	if err := regen(wrong); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected the fresh budget to cap at %d, got %v", maxTOTPAttempts, err)
	}
}

// TestCompletedEnrollmentClearsASpentBudget: a new secret is a fresh guessing
// space, so a budget spent before (re-)enrollment must not lock the first
// login with the new secret.
func TestCompletedEnrollmentClearsASpentBudget(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()

	registered, err := auth.Register(ctx, "owner@example.com", totpWindowTestPassword)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, purpose := range []totpPurpose{totpPurposeSignIn, totpPurposeStepUp} {
		budget := totp.budget(ctx, purpose, registered.AccountID)
		for range maxTOTPAttempts {
			if _, err := budget.reserve(now); err != nil {
				t.Fatalf("reserve %s: %v", purpose, err)
			}
		}
	}

	start, err := totp.StartEnrollment(ctx, registered.AccountID, StepUp{SessionTokenHash: security.HashToken(registered.SessionToken), CurrentPassword: totpWindowTestPassword})
	if err != nil {
		t.Fatalf("StartEnrollment: %v", err)
	}
	secret, err := security.DecodeTOTPSecretBase32(start.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if _, err := totp.CompleteEnrollment(ctx, registered.AccountID, security.HashToken(registered.SessionToken),
		security.GenerateTOTPCode(secret, now.Unix()/security.TOTPStepSeconds)); err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	if _, err := totp.VerifyChallenge(fromClient("192.0.2.4"), freshChallengeID(t, totp, registered.AccountID), wrongTOTPCode(t, secret, later)); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("expected a plain wrong-code answer after enrollment, got %v", err)
	}
}

// TestEnrollmentTOTPBudgetIsKeyedByClientAndAccount: enrollment guesses from
// one client spend the account's enrollment bucket for every client, and do
// not touch the step-up or sign-in budgets.
func TestEnrollmentTOTPBudgetIsKeyedByClientAndAccount(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	accountID, sessionToken, secret := startPendingEnrollment(t, auth, totp)
	sessionHash := security.HashToken(sessionToken)

	wrong := wrongTOTPCode(t, secret, now)
	for i := range maxTOTPAttempts {
		if _, err := totp.CompleteEnrollment(fromClient("203.0.113.7"), accountID, sessionHash, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("guess %d: expected ErrTOTPInvalidCode, got %v", i+1, err)
		}
	}
	correct := security.GenerateTOTPCode(secret, now.Unix()/security.TOTPStepSeconds)
	if _, err := totp.CompleteEnrollment(fromClient("198.51.100.9"), accountID, sessionHash, correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("another client against the spent enrollment bucket: expected ErrTOTPLocked, got %v", err)
	}
	for _, purpose := range []totpPurpose{totpPurposeSignIn, totpPurposeStepUp} {
		if _, err := totp.budget(fromClient("203.0.113.7"), purpose, accountID).reserve(now); err != nil {
			t.Fatalf("%s budget was spent by enrollment guesses: %v", purpose, err)
		}
	}
}

// TestConcurrentDisableGuessesSpendExactlyTheStepUpCap: disable has no
// per-challenge budget to burn first, so a concurrent burst drives every
// request into the reservation; exactly the cap get a code check.
func TestConcurrentDisableGuessesSpendExactlyTheStepUpCap(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := fromClient("203.0.113.7")
	accountID, _, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong := wrongTOTPCode(t, secret, later)

	const guesses = 2 * maxTOTPAttempts
	results := make(chan error, guesses)
	var wg sync.WaitGroup
	for range guesses {
		wg.Go(func() {
			results <- totp.Disable(ctx, accountID, StepUp{CurrentPassword: totpWindowTestPassword, TOTPCode: wrong})
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
	if invalid != maxTOTPAttempts || locked != guesses-maxTOTPAttempts {
		t.Fatalf("invalid=%d locked=%d, want %d and %d", invalid, locked, maxTOTPAttempts, guesses-maxTOTPAttempts)
	}
}

// TestDisableSharesTheStepUpTOTPBudget: disable's wrong codes spend the
// step-up budget every in-session code check shares, and leave the sign-in
// budget alone.
func TestDisableSharesTheStepUpTOTPBudget(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := fromClient("203.0.113.7")
	accountID, sessionToken, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong := wrongTOTPCode(t, secret, later)
	for range maxTOTPAttempts {
		if err := totp.Disable(ctx, accountID, StepUp{CurrentPassword: totpWindowTestPassword, TOTPCode: wrong}); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode, got %v", err)
		}
	}

	correct := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	if err := totp.Disable(ctx, accountID, StepUp{CurrentPassword: totpWindowTestPassword, TOTPCode: correct}); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected disable to be locked, got %v", err)
	}
	if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}, correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected regeneration to share the step-up lock, got %v", err)
	}
	if _, err := totp.VerifyChallenge(ctx, loginChallengeID(t, auth), correct); err != nil {
		t.Fatalf("expected sign-in to stay reachable, got %v", err)
	}

	// A wrong password never reaches the code check, so it spends nothing.
	if err := totp.Disable(ctx, accountID, StepUp{CurrentPassword: "wrong password entirely", TOTPCode: wrong}); !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
	}
}

// Recovery-code regeneration on an enrolled account spends the step-up
// budget: otherwise it would be a code oracle bounded only by the route
// limiter.
func TestRegenerateRecoveryCodeSharesTheStepUpTOTPBudget(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := fromClient("203.0.113.7")
	accountID, sessionToken, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	wrong := wrongTOTPCode(t, secret, later)
	for range maxTOTPAttempts {
		if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}, wrong); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode, got %v", err)
		}
	}

	correct := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}, correct); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected regeneration to be locked, got %v", err)
	}
	if err := totp.Disable(ctx, accountID, StepUp{CurrentPassword: totpWindowTestPassword, TOTPCode: correct}); !errors.Is(err, ErrTOTPLocked) {
		t.Fatalf("expected disable to share the lock, got %v", err)
	}
}

// A missing code (an old client) and a wrong password both stop before the
// budget: a full budget of either leaves the correct code usable.
func TestRegenerateRecoveryCodeMissingCodeSpendsNoTOTPAttempt(t *testing.T) {
	auth, totp, now := fixedTOTPClock(t)
	ctx := context.Background()
	accountID, sessionToken, secret, _ := enrollTOTP(t, auth, totp, now)

	later := now.Add(security.TOTPStepSeconds * time.Second)
	setTOTPClock(auth, totp, later)
	correct := security.GenerateTOTPCode(secret, later.Unix()/security.TOTPStepSeconds)
	for range maxTOTPAttempts {
		if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}, ""); !errors.Is(err, ErrTOTPInvalidCode) {
			t.Fatalf("expected ErrTOTPInvalidCode for a missing code, got %v", err)
		}
		if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: "wrong password entirely"}, correct); !errors.Is(err, ErrInvalidCurrentPassword) {
			t.Fatalf("expected ErrInvalidCurrentPassword, got %v", err)
		}
	}

	if _, err := auth.RegenerateRecoveryCode(ctx, accountID, StepUp{SessionTokenHash: security.HashToken(sessionToken), CurrentPassword: totpWindowTestPassword}, correct); err != nil {
		t.Fatalf("expected the correct code to work after a budget of missing codes, got %v", err)
	}
}

// TestTOTPReservationRefundStaysInItsWindow: a sign-in success refunds its
// reservation only into the window it was booked in.
func TestTOTPReservationRefundStaysInItsWindow(t *testing.T) {
	limiter := newTOTPAttemptLimiter()
	base := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	keys := []string{"a", "b"}

	old, _, ok := limiter.reserve(keys, base)
	if !ok {
		t.Fatal("expected the first reservation to pass")
	}
	next := base.Add(TOTPAttemptWindow)
	for range maxTOTPAttempts {
		if _, _, ok := limiter.reserve(keys, next); !ok {
			t.Fatal("expected the new window to grant its full budget")
		}
	}
	limiter.refund(old)
	if _, _, ok := limiter.reserve(keys, next); ok {
		t.Fatal("a refund of the previous window's reservation granted the new window an extra attempt")
	}
}

// TestTOTPAttemptLimiterSweepKeepsInWindowEntries: the sweep deletes only
// expired buckets, never one still counting.
func TestTOTPAttemptLimiterSweepKeepsInWindowEntries(t *testing.T) {
	limiter := newTOTPAttemptLimiter()
	base := time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC)
	limiter.reserve([]string{"expired"}, base)
	later := base.Add(TOTPAttemptWindow)
	for range maxTOTPAttempts {
		limiter.reserve([]string{"live"}, later)
	}
	limiter.opsSinceSweep = totpAttemptSweepInterval
	limiter.reserve([]string{"other"}, later)

	if _, ok := limiter.entries["expired"]; ok {
		t.Fatal("expected the expired bucket to be swept")
	}
	if limiter.entries["live"].count != maxTOTPAttempts {
		t.Fatalf("sweep touched an in-window bucket: %#v", limiter.entries["live"])
	}
}
