package db

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// TestInstantComparesHoldWithinOneSecond pins the SQL instant compares on a
// whole-second value ("…:05Z") against one later in the same second
// ("…:05.5Z"), the pair that sorts backwards as RFC3339Nano text.
func TestInstantComparesHoldWithinOneSecond(t *testing.T) {
	ctx := context.Background()
	whole := time.Date(2026, 11, 15, 10, 0, 5, 0, time.UTC)
	later := whole.Add(500 * time.Millisecond)

	t.Run("expired sessions sweep", func(t *testing.T) {
		store := openTestStore(t)
		account := expiredRowsFixtureAccount(t, store, "instant-sessions")
		createSessionExpiringAt(t, store, account.ID, "expired-at-whole", whole)
		createSessionExpiringAt(t, store, account.ID, "live-past-later", later.Add(250*time.Millisecond))

		deleted, err := store.DeleteExpiredSessions(ctx, later, 0)
		if err != nil {
			t.Fatalf("delete expired sessions: %v", err)
		}
		if deleted != 1 {
			t.Fatalf("expected only the session expired at %s deleted, got %d", whole, deleted)
		}
		if _, err := store.FindSessionByTokenHash(ctx, "hash-live-past-later"); err != nil {
			t.Fatalf("expected the live session kept, got %v", err)
		}
	})

	t.Run("expired reset tokens and challenges sweep", func(t *testing.T) {
		store := openTestStore(t)
		for _, expiresAt := range []struct {
			suffix string
			at     time.Time
		}{{"expired", whole}, {"live", later.Add(250 * time.Millisecond)}} {
			account := expiredRowsFixtureAccount(t, store, "instant-sweep-"+expiresAt.suffix)
			if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
				AccountID: account.ID,
				TokenHash: "hash-reset-" + expiresAt.suffix,
				CreatedAt: whole.Add(-time.Minute),
				ExpiresAt: expiresAt.at,
			}, account.RecoveryCodeHash); err != nil {
				t.Fatalf("seed reset token: %v", err)
			}
			if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
				ChallengeIDHash: "hash-challenge-" + expiresAt.suffix,
				AccountID:       account.ID,
				CreatedAt:       whole.Add(-time.Minute),
				ExpiresAt:       expiresAt.at,
			}); err != nil {
				t.Fatalf("seed challenge: %v", err)
			}
		}

		if deleted, err := store.DeleteExpiredPasswordResetTokens(ctx, later, 0); err != nil || deleted != 1 {
			t.Fatalf("expected one reset token deleted, got %d, %v", deleted, err)
		}
		if deleted, err := store.DeleteExpiredTOTPChallenges(ctx, later, 0); err != nil || deleted != 1 {
			t.Fatalf("expected one challenge deleted, got %d, %v", deleted, err)
		}
		if _, err := store.FindTOTPChallengeByHash(ctx, "hash-challenge-live"); err != nil {
			t.Fatalf("expected the live challenge kept, got %v", err)
		}
	})

	t.Run("reset token claim", func(t *testing.T) {
		store := openTestStore(t)
		account := expiredRowsFixtureAccount(t, store, "instant-reset")
		if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
			AccountID: account.ID,
			TokenHash: "hash-instant-reset",
			CreatedAt: whole.Add(-time.Minute),
			ExpiresAt: whole,
		}, account.RecoveryCodeHash); err != nil {
			t.Fatalf("seed reset token: %v", err)
		}

		if _, err := store.ConsumePasswordResetToken(ctx, "hash-instant-reset", later); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected a token expired at %s refused at %s, got %v", whole, later, err)
		}
	})

	t.Run("lapsed account sweep", func(t *testing.T) {
		store := openTestStore(t)
		const accountID = "managed-lapsed-at-whole"
		createLapseTestAccount(t, store, accountID, "managed")
		if err := store.SetAccountLapsed(ctx, accountID, whole); err != nil {
			t.Fatalf("lapse account: %v", err)
		}

		ids, err := store.ListLapsedManagedAccountIDs(ctx, later, 0)
		if err != nil {
			t.Fatalf("list lapsed accounts: %v", err)
		}
		if len(ids) != 1 || ids[0] != accountID {
			t.Fatalf("expected %q past the cutoff, got %#v", accountID, ids)
		}
		if err := store.DeleteLapsedManagedAccount(ctx, accountID, later); err != nil {
			t.Fatalf("delete lapsed account: %v", err)
		}
	})
}

// TestNoTextInstantCompareInSQL keeps the next query from comparing, ordering
// or aggregating a stored *_at column as text; wrap both sides in julianday().
// It reads every string literal of this package's production sources and
// every migration, so a column-to-column or literal compare is caught as well
// as a ?-bound one.
func TestNoTextInstantCompareInSQL(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	fset := token.NewFileSet()
	instantQueries := 0
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, source, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", source, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("%s: unquote literal: %v", fset.Position(literal.Pos()), err)
			}
			if strings.Contains(text, "julianday(") {
				instantQueries++
			}
			for _, match := range textInstantCompares(text) {
				t.Errorf("%s: instant compared as text: %q", fset.Position(literal.Pos()), match)
			}
			return true
		})
	}
	if instantQueries == 0 {
		t.Fatal("scanned no julianday() query: the source walk is reading the wrong files")
	}

	migrations, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, entry := range migrations {
		body, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, match := range textInstantCompares(string(body)) {
			t.Errorf("migrations/%s: instant compared as text: %q", entry.Name(), match)
		}
	}
}

// TestTextInstantCompareDetector pins the detector itself, so a pattern edit
// cannot turn TestNoTextInstantCompareInSQL into a check that never fails.
func TestTextInstantCompareDetector(t *testing.T) {
	for _, sql := range []string{
		`WHERE expires_at <= ?`,
		`WHERE ? > expires_at`,
		`WHERE s.expires_at < CURRENT_TIMESTAMP`,
		`WHERE lapsed_at < accounts.created_at`,
		`WHERE created_at BETWEEN ? AND ?`,
		`SELECT MAX(updated_at) FROM encrypted_blobs`,
		`ORDER BY created_at DESC`,
		`ORDER BY device_id, d.last_seen_at LIMIT ?`,
	} {
		if len(textInstantCompares(sql)) == 0 {
			t.Errorf("detector missed a text instant compare: %q", sql)
		}
	}
	for _, sql := range []string{
		`WHERE julianday(expires_at) <= julianday(?) OR julianday(expires_at) IS NULL`,
		`WHERE julianday(s.expires_at) > julianday(?)`,
		`ORDER BY julianday(created_at), device_id`,
		`SET consumed_at = ? WHERE consumed_at IS NULL`,
		`lapsed_at = COALESCE(lapsed_at, ?)`,
		"-- rows expire when expires_at < now\nSELECT 1",
		`window_started_unix < ?`,
	} {
		if matches := textInstantCompares(sql); len(matches) != 0 {
			t.Errorf("detector flagged %q in %q", matches, sql)
		}
	}
}

const bareInstantColumn = `(?:\w+\.)?\w+_at`

var (
	sqlLineComment     = regexp.MustCompile(`--[^\n]*`)
	instantLeftOfCmp   = regexp.MustCompile(`(?i)(?:^|[^\w.(])` + bareInstantColumn + `\s*(?:<=|>=|<|>|\bBETWEEN\b)`)
	instantRightOfCmp  = regexp.MustCompile(`(?:<=|>=|<|>)\s*` + bareInstantColumn + `\b`)
	instantAggregate   = regexp.MustCompile(`(?i)\b(?:MAX|MIN)\s*\(\s*` + bareInstantColumn + `\s*\)`)
	orderByTerms       = regexp.MustCompile(`(?is)\bORDER\s+BY\s+(.*?)(?:\bLIMIT\b|\)|;|$)`)
	bareInstantOrdered = regexp.MustCompile(`(?i)^` + bareInstantColumn + `(?:\s+(?:ASC|DESC))?$`)
)

// textInstantCompares returns each fragment of sql that compares, orders or
// aggregates a bare *_at column, one not wrapped in julianday().
func textInstantCompares(sql string) []string {
	sql = sqlLineComment.ReplaceAllString(sql, "")
	var matches []string
	for _, pattern := range []*regexp.Regexp{instantLeftOfCmp, instantRightOfCmp, instantAggregate} {
		matches = append(matches, pattern.FindAllString(sql, -1)...)
	}
	for _, clause := range orderByTerms.FindAllStringSubmatch(sql, -1) {
		for _, term := range strings.Split(clause[1], ",") {
			if term = strings.TrimSpace(term); bareInstantOrdered.MatchString(term) {
				matches = append(matches, "ORDER BY "+term)
			}
		}
	}
	return matches
}
