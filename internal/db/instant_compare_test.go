package db

import (
	"bytes"
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
		`AND (lapsed_at < ? OR lapsed_at IS NULL)`,
		`WHERE julianday(expires_at) <= ?`,
		`WHERE ? > julianday(expires_at)`,
		`WHERE created_at BETWEEN ? AND ?`,
		`WHERE julianday(created_at) BETWEEN julianday(?) AND ?`,
		`SELECT MAX(updated_at) FROM encrypted_blobs`,
		`ORDER BY created_at DESC`,
		`ORDER BY device_id, d.last_seen_at LIMIT ?`,
		`ORDER BY julianday(lapsed_at), created_at LIMIT ?`,
		`WHERE note <> '--' AND expires_at < ?`,
		`WHERE julianday(COALESCE(lapsed_at, created_at)) <= ?`,
		`WHERE ? > julianday(COALESCE(lapsed_at, created_at))`,
		`WHERE COALESCE(lapsed_at, created_at) < julianday(?)`,
		`WHERE julianday(expires_at) + 1 > ?`,
		`ORDER BY COALESCE(lapsed_at, created_at) LIMIT ?`,
		`SELECT MIN(COALESCE(updated_at, created_at)) FROM encrypted_blobs`,
		"it's\nWHERE expires_at < ?",
		`WHERE created_at NOT BETWEEN ? AND ?`,
		`WHERE CAST(expires_at AS REAL) < ?`,
		`WHERE (SELECT login FROM accounts WHERE julianday(lapsed_at) > julianday(?)) > julianday(?)`,
		`WHERE julianday(created_at) || '' > julianday(?)`,
		`SELECT MAX(julianday(created_at, updated_at`,
	} {
		if len(textInstantCompares(sql)) == 0 {
			t.Errorf("detector missed a text instant compare: %q", sql)
		}
	}
	for _, sql := range []string{
		`WHERE julianday(expires_at) <= julianday(?) OR julianday(expires_at) IS NULL`,
		`WHERE julianday(s.expires_at) > julianday(?)`,
		`WHERE julianday(created_at) BETWEEN julianday(?) AND julianday(?)`,
		`ORDER BY julianday(created_at), device_id`,
		`WHERE id IN (SELECT id FROM u ORDER BY julianday(created_at)) ORDER BY id`,
		`SET consumed_at = ? WHERE consumed_at IS NULL`,
		`WHERE consumed_at <> ?`,
		`lapsed_at = COALESCE(lapsed_at, ?)`,
		"-- rows expire when expires_at < now\nSELECT 1",
		"/* rows where expires_at < now */ SELECT 1",
		`window_started_unix < ?`,
		`WHERE julianday(COALESCE(lapsed_at, created_at)) <= julianday(?)`,
		`ORDER BY julianday(COALESCE(lapsed_at, created_at)), id`,
		`WHERE julianday(expires_at) - julianday(?) > 0`,
		`WHERE (julianday(?) - julianday(created_at)) * 86400 >= 30.5`,
		`WHERE julianday(expires_at) + 1 > julianday(?)`,
		"it's\n-- rows where expires_at < now\nSELECT 1",
		`WHERE note = 'it''s' /* expires_at < now */ AND julianday(expires_at) > julianday(?)`,
		`WHERE (SELECT MAX(julianday(created_at)) FROM devices WHERE account_id = ?) > julianday(?)`,
		`SELECT id, ROW_NUMBER() OVER (ORDER BY julianday(created_at) ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM devices`,
	} {
		if matches := textInstantCompares(sql); len(matches) != 0 {
			t.Errorf("detector flagged %q in %q", matches, sql)
		}
	}
}

type sqlTokenKind int

const (
	sqlWord sqlTokenKind = iota
	sqlNumber
	sqlString
	sqlParam
	sqlSymbol
)

// sqlToken is one lexical unit of a SQL text: a word (keyword, function name
// or possibly qualified column), a number, a quoted string, a ? parameter or
// an operator.
type sqlToken struct {
	kind sqlTokenKind
	text string
}

var (
	instantColumn   = regexp.MustCompile(`^(?:\w+\.)*\w+_at$`)
	instantCompares = map[string]bool{"<": true, "<=": true, ">": true, ">=": true}
	// operandBoundaries, with instantCompares, end a compared operand at
	// nesting depth 0. ROWS, RANGE and GROUPS keep a window frame's BETWEEN
	// from reading the ORDER BY key as its operand.
	operandBoundaries = map[string]bool{
		",": true, ";": true, "=": true, "==": true, "<>": true, "!=": true,
		"ROWS": true, "RANGE": true, "GROUPS": true,
		"AND": true, "OR": true, "NOT": true, "WHERE": true, "ON": true, "WHEN": true,
		"THEN": true, "ELSE": true, "END": true, "CASE": true, "SELECT": true,
		"SET": true, "FROM": true, "AS": true, "HAVING": true, "BETWEEN": true,
		"IS": true, "IN": true, "LIKE": true, "GLOB": true, "MATCH": true,
		"REGEXP": true, "ESCAPE": true, "ORDER": true, "GROUP": true, "BY": true,
		"LIMIT": true, "OFFSET": true, "RETURNING": true, "VALUES": true,
		"UNION": true, "INTERSECT": true, "EXCEPT": true, "JOIN": true,
		"USING": true, "DO": true, "WITH": true,
	}
	twoByteOperators = map[string]bool{
		"<=": true, ">=": true, "<>": true, "!=": true, "==": true, "||": true, "<<": true, ">>": true,
	}
)

// textInstantCompares returns each fragment of sql that compares, orders or
// aggregates a *_at column outside julianday(), or compares a julianday()
// value with one that is neither julianday() nor a number: SQLite sorts every
// number before every text value.
func textInstantCompares(sql string) []string {
	tokens := lexSQL(sql)
	var matches []string
	for i, token := range tokens {
		switch {
		case token.kind == sqlSymbol && instantCompares[token.text]:
			left, right := operandBefore(tokens, i), operandAfter(tokens, i+1)
			if instantOperandsMismatch(left, right) {
				matches = append(matches, joinSQL(tokens[i-len(left):i+1+len(right)]))
			}
		case isSQLKeyword(token, "BETWEEN"):
			leftEnd := i
			if i > 0 && isSQLKeyword(tokens[i-1], "NOT") {
				leftEnd--
			}
			left, low := operandBefore(tokens, leftEnd), operandAfter(tokens, i+1)
			and := i + 1 + len(low)
			if and >= len(tokens) || !isSQLKeyword(tokens[and], "AND") {
				continue
			}
			high := operandAfter(tokens, and+1)
			if instantOperandsMismatch(left, low, high) {
				matches = append(matches, joinSQL(tokens[leftEnd-len(left):and+1+len(high)]))
			}
		case (isSQLKeyword(token, "MAX") || isSQLKeyword(token, "MIN")) && isSQLCall(tokens, i):
			end := closingParen(tokens, i+1)
			if end < 0 {
				end = len(tokens) - 1
			}
			call := tokens[i : end+1]
			if hasBareInstant(call[2:]) {
				matches = append(matches, joinSQL(call))
			}
		case isSQLKeyword(token, "ORDER") && i+1 < len(tokens) && isSQLKeyword(tokens[i+1], "BY"):
			for _, term := range orderByTerms(tokens[i+2:]) {
				if hasBareInstant(term) {
					matches = append(matches, "ORDER BY "+joinSQL(term))
				}
			}
		}
	}
	return matches
}

func instantOperandsMismatch(operands ...[]sqlToken) bool {
	julian, text := 0, 0
	for _, operand := range operands {
		switch {
		case len(operand) == 0:
		case hasBareInstant(operand):
			return true
		case hasJuliandayCall(operand):
			julian++
		case isNumericLiteral(operand):
		default:
			text++
		}
	}
	return julian > 0 && text > 0
}

// hasBareInstant reports a *_at column that no julianday() call wraps.
func hasBareInstant(tokens []sqlToken) bool {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].kind != sqlWord {
			continue
		}
		if isSQLCall(tokens, i) {
			if end := closingParen(tokens, i+1); end >= 0 && isSQLKeyword(tokens[i], "julianday") {
				i = end
			}
			continue
		}
		if instantColumn.MatchString(tokens[i].text) {
			return true
		}
	}
	return false
}

// hasJuliandayCall reports a julianday() call that yields the operand's value:
// one outside a subquery's FROM tail, in an operand no top-level || turns
// into text.
func hasJuliandayCall(tokens []sqlToken) bool {
	found := false
	// One frame per open parenthesis: 'g' a group or call, 's' a subquery's
	// select list, 'r' the rest of that subquery.
	var frames []byte
	for i, token := range tokens {
		switch {
		case token.text == "(":
			frame := byte('g')
			if i+1 < len(tokens) && isSQLKeyword(tokens[i+1], "SELECT") {
				frame = 's'
			}
			frames = append(frames, frame)
		case token.text == ")":
			if len(frames) > 0 {
				frames = frames[:len(frames)-1]
			}
		case len(frames) > 0 && frames[len(frames)-1] == 's' && isSQLKeyword(token, "FROM"):
			frames[len(frames)-1] = 'r'
		case bytes.IndexByte(frames, 'r') >= 0:
		case token.text == "||" && len(frames) == 0:
			return false
		case isSQLKeyword(token, "julianday") && isSQLCall(tokens, i):
			found = true
		}
	}
	return found
}

func isNumericLiteral(tokens []sqlToken) bool {
	if len(tokens) == 2 && (tokens[0].text == "-" || tokens[0].text == "+") {
		tokens = tokens[1:]
	}
	return len(tokens) == 1 && tokens[0].kind == sqlNumber
}

// operandBefore returns the expression that ends just before tokens[end].
func operandBefore(tokens []sqlToken, end int) []sqlToken {
	depth, start := 0, end
	for ; start > 0; start-- {
		token := tokens[start-1]
		if token.text == ")" {
			depth++
		} else if token.text == "(" {
			if depth == 0 {
				break
			}
			depth--
		} else if depth == 0 && isOperandBoundary(token) {
			break
		}
	}
	return tokens[start:end]
}

// operandAfter returns the expression that starts at tokens[start].
func operandAfter(tokens []sqlToken, start int) []sqlToken {
	depth, end := 0, start
	for ; end < len(tokens); end++ {
		token := tokens[end]
		if token.text == "(" {
			depth++
		} else if token.text == ")" {
			if depth == 0 {
				break
			}
			depth--
		} else if depth == 0 && isOperandBoundary(token) {
			break
		}
	}
	return tokens[start:end]
}

// orderByTerms splits the ORDER BY list that tokens open at its top-level
// commas, ending it at a closing parenthesis, a semicolon, LIMIT or OFFSET.
func orderByTerms(tokens []sqlToken) [][]sqlToken {
	var terms [][]sqlToken
	depth, start, i := 0, 0, 0
scan:
	for ; i < len(tokens); i++ {
		switch token := tokens[i]; {
		case token.text == "(":
			depth++
		case token.text == ")":
			if depth == 0 {
				break scan
			}
			depth--
		case depth > 0:
		case token.text == ",":
			terms = append(terms, tokens[start:i])
			start = i + 1
		case token.text == ";", isSQLKeyword(token, "LIMIT"), isSQLKeyword(token, "OFFSET"):
			break scan
		}
	}
	return append(terms, tokens[start:i])
}

// closingParen returns the index of the parenthesis that closes
// tokens[open], or -1 when it is never closed.
func closingParen(tokens []sqlToken, open int) int {
	depth := 0
	for i := open; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			depth++
		case ")":
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isSQLCall(tokens []sqlToken, i int) bool {
	return tokens[i].kind == sqlWord && i+1 < len(tokens) && tokens[i+1].text == "("
}

func isSQLKeyword(token sqlToken, keyword string) bool {
	return token.kind == sqlWord && strings.EqualFold(token.text, keyword)
}

func isOperandBoundary(token sqlToken) bool {
	switch token.kind {
	case sqlSymbol:
		return operandBoundaries[token.text] || instantCompares[token.text]
	case sqlWord:
		return operandBoundaries[strings.ToUpper(token.text)]
	}
	return false
}

func joinSQL(tokens []sqlToken) string {
	texts := make([]string, len(tokens))
	for i, token := range tokens {
		texts[i] = token.text
	}
	return strings.Join(texts, " ")
}

// lexSQL splits sql into tokens and drops -- and /* */ comments. A quote with
// no closing partner (an apostrophe in a non-SQL literal) opens no string.
func lexSQL(sql string) []sqlToken {
	var tokens []sqlToken
	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.HasPrefix(sql[i:], "--"):
			end := strings.IndexByte(sql[i:], '\n')
			if end < 0 {
				return tokens
			}
			i += end
		case strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return tokens
			}
			i += 2 + end + 2
		case c == '\'' || c == '"' || c == '`':
			end := closingQuote(sql, i)
			switch {
			case end < 0:
				tokens = append(tokens, sqlToken{sqlSymbol, string(c)})
				i++
				continue
			case c == '\'':
				tokens = append(tokens, sqlToken{sqlString, sql[i : end+1]})
			default:
				tokens = append(tokens, sqlToken{sqlWord, sql[i+1 : end]})
			}
			i = end + 1
		case c == '?':
			end := i + 1
			for end < len(sql) && isDigitByte(sql[end]) {
				end++
			}
			tokens = append(tokens, sqlToken{sqlParam, sql[i:end]})
			i = end
		case isWordByte(c) || (c == '.' && i+1 < len(sql) && isDigitByte(sql[i+1])):
			end := i
			for end < len(sql) && (isWordByte(sql[end]) || sql[end] == '.') {
				end++
			}
			kind := sqlWord
			if isDigitByte(c) || c == '.' {
				kind = sqlNumber
			}
			tokens = append(tokens, sqlToken{kind, sql[i:end]})
			i = end
		default:
			width := 1
			if i+1 < len(sql) && twoByteOperators[sql[i:i+2]] {
				width = 2
			}
			tokens = append(tokens, sqlToken{sqlSymbol, sql[i : i+width]})
			i += width
		}
	}
	return tokens
}

// closingQuote returns the index of the quote that closes sql[open], reading
// a doubled quote as an escaped one, or -1 when none does.
func closingQuote(sql string, open int) int {
	quote := sql[open]
	for i := open + 1; i < len(sql); i++ {
		if sql[i] != quote {
			continue
		}
		if i+1 < len(sql) && sql[i+1] == quote {
			i++
			continue
		}
		return i
	}
	return -1
}

func isDigitByte(c byte) bool {
	return c >= '0' && c <= '9'
}

func isWordByte(c byte) bool {
	return c == '_' || isDigitByte(c) || (c|0x20 >= 'a' && c|0x20 <= 'z')
}
