package services

import (
	"context"
	"strings"
	"sync"
	"time"
)

// TOTPAttemptWindow and maxTOTPAttempts are each TOTP budget's figures: a code
// check draws one attempt from a client bucket and an account bucket of its
// purpose, and is refused while either holds maxTOTPAttempts in the window.
// 5 per 15 minutes holds one budget to 480 guesses a day, ~0.14 % against the
// 3 codes the skew window accepts.
const (
	TOTPAttemptWindow = 15 * time.Minute
	maxTOTPAttempts   = 5
)

// totpPurpose names one budget. The budgets are separate so that spending one
// never closes another: a password holder without a session reaches only the
// sign-in budget, so the owner's in-session step-ups stay reachable while it
// is spent, and a stolen session reaches only the step-up and enrollment
// budgets, never a second sign-in guess budget.
type totpPurpose string

const (
	totpPurposeSignIn totpPurpose = "totp.signin"
	totpPurposeEnroll totpPurpose = "totp.enroll"
	totpPurposeStepUp totpPurpose = "totp.stepup"
)

type clientKeyContextKey struct{}

// WithClientKey records the caller's rate-limit client key (its address as the
// transport resolved it) on the request context, for the TOTP budgets' client
// buckets.
func WithClientKey(ctx context.Context, clientKey string) context.Context {
	return context.WithValue(ctx, clientKeyContextKey{}, clientKey)
}

func clientKeyFrom(ctx context.Context) string {
	key, _ := ctx.Value(clientKeyContextKey{}).(string)
	key = strings.TrimSpace(key)
	if key == "" {
		return "unknown"
	}
	return key
}

// totpBudgetKeys names the two buckets an attempt of purpose draws. The client
// bucket carries the account: accounts sharing an address never draw each
// other's budget, and a success on one account (which clears its client
// bucket) cannot forgive failures the same address spent against another.
func totpBudgetKeys(purpose totpPurpose, clientKey string, accountID string) (client string, account string) {
	return string(purpose) + ":client:" + accountID + ":" + clientKey,
		string(purpose) + ":account:" + accountID
}

// totpAttemptSweepInterval bounds the map the same way the HTTP limiter's
// sweep does: only expired entries are deleted, never an in-window one.
const totpAttemptSweepInterval = 1024

type totpAttemptEntry struct {
	count       int
	windowStart time.Time
}

// totpAttemptLimiter holds every TOTP budget's buckets in memory. A reserve
// checks and charges all of an attempt's buckets under one lock, so
// concurrent guesses cannot each pass a count the others have not charged yet.
type totpAttemptLimiter struct {
	mu            sync.Mutex
	entries       map[string]totpAttemptEntry
	opsSinceSweep int
}

func newTOTPAttemptLimiter() *totpAttemptLimiter {
	return &totpAttemptLimiter{entries: make(map[string]totpAttemptEntry)}
}

// totpReservation is one attempt booked under each of its buckets, with the
// window it was booked in, so a refund never returns a slot to a later window.
type totpReservation struct {
	keys         []string
	windowStarts []time.Time
}

// reserve books one attempt under every key, or none: when any key holds
// maxTOTPAttempts in its window it returns ok false and how long until the
// last spent window ends.
func (l *totpAttemptLimiter) reserve(keys []string, now time.Time) (totpReservation, time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepLocked(now)

	var retryAfter time.Duration
	for _, key := range keys {
		entry, ok := l.entries[key]
		if !ok || now.Sub(entry.windowStart) >= TOTPAttemptWindow {
			continue
		}
		if entry.count >= maxTOTPAttempts {
			retryAfter = max(retryAfter, entry.windowStart.Add(TOTPAttemptWindow).Sub(now))
		}
	}
	if retryAfter > 0 {
		return totpReservation{}, retryAfter, false
	}

	reservation := totpReservation{keys: keys, windowStarts: make([]time.Time, len(keys))}
	for i, key := range keys {
		entry, ok := l.entries[key]
		if !ok || now.Sub(entry.windowStart) >= TOTPAttemptWindow {
			entry = totpAttemptEntry{windowStart: now}
		}
		entry.count++
		l.entries[key] = entry
		reservation.windowStarts[i] = entry.windowStart
	}
	return reservation, 0, true
}

// refund gives a reservation's attempt back to each bucket still in the
// window it was booked in.
func (l *totpAttemptLimiter) refund(reservation totpReservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, key := range reservation.keys {
		entry, ok := l.entries[key]
		if !ok || !entry.windowStart.Equal(reservation.windowStarts[i]) || entry.count <= 0 {
			continue
		}
		entry.count--
		l.entries[key] = entry
	}
}

func (l *totpAttemptLimiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		delete(l.entries, key)
	}
}

func (l *totpAttemptLimiter) maybeSweepLocked(now time.Time) {
	l.opsSinceSweep++
	if l.opsSinceSweep < totpAttemptSweepInterval {
		return
	}
	l.opsSinceSweep = 0
	for key, entry := range l.entries {
		if now.Sub(entry.windowStart) >= TOTPAttemptWindow {
			delete(l.entries, key)
		}
	}
}

// totpBudget is one attempt's view of its purpose's buckets.
type totpBudget struct {
	limiter *totpAttemptLimiter
	client  string
	account string
}

func (s *TOTPService) budget(ctx context.Context, purpose totpPurpose, accountID string) totpBudget {
	client, account := totpBudgetKeys(purpose, clientKeyFrom(ctx), accountID)
	return totpBudget{limiter: s.attempts, client: client, account: account}
}

// reserve draws one attempt before a code is checked; a spent budget returns
// *TOTPLockedError, so a correct code is refused too. The caller keeps the
// reservation when the code is wrong and refunds it on success.
func (b totpBudget) reserve(now time.Time) (totpReservation, error) {
	reservation, retryAfter, ok := b.limiter.reserve([]string{b.client, b.account}, now)
	if !ok {
		return totpReservation{}, &TOTPLockedError{RetryAfter: retryAfter}
	}
	return reservation, nil
}

// succeedSignIn is the sign-in success: it forgives only this client. The
// account bucket pools every client's failures against the account, so the
// owner's own sign-in must not wipe what an attacker elsewhere spent.
func (b totpBudget) succeedSignIn(reservation totpReservation) {
	b.limiter.refund(reservation)
	b.limiter.reset(b.client)
}

// succeedInSession is the success of a check only a live session of the
// account reaches: both buckets hold the owner's own mistakes, so both clear.
func (b totpBudget) succeedInSession() {
	b.limiter.reset(b.client, b.account)
}
