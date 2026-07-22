package api

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// openRawReadConnection opens an independent raw connection to the same
// database file — the second-connection technique the fault-injection tests
// use, applied read-only so a test can prove what actually reached disk.
func openRawReadConnection(t *testing.T, dbPath string) *sql.DB {
	t.Helper()

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	return raw
}

// TestSessionTokensAndRecoveryCodesPersistOnlyAsHashes proves the hash-only
// storage claims against the real database file (formerly planned
// regressions in SECURITY.md): no sessions column carries the raw bearer
// token — the hash column carries exactly security.HashToken of it — and the
// account row holds the recovery code only as a verifying bcrypt hash.
func TestSessionTokensAndRecoveryCodesPersistOnlyAsHashes(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})
	registered := registerOwner(t, handler)

	raw := openRawReadConnection(t, dbPath)

	rows, err := raw.Query(`SELECT id, account_id, token_hash, created_at, last_seen_at, expires_at FROM sessions`)
	if err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	defer func() { _ = rows.Close() }()

	sawHash := false
	sessionCount := 0
	for rows.Next() {
		sessionCount++
		var id, accountID, tokenHash, createdAt, lastSeenAt, expiresAt string
		if err := rows.Scan(&id, &accountID, &tokenHash, &createdAt, &lastSeenAt, &expiresAt); err != nil {
			t.Fatalf("scan session row: %v", err)
		}
		for _, value := range []string{id, accountID, tokenHash, createdAt, lastSeenAt, expiresAt} {
			if value == registered.SessionToken {
				t.Fatal("raw session token found persisted in the sessions table")
			}
		}
		if tokenHash == security.HashToken(registered.SessionToken) {
			sawHash = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate sessions: %v", err)
	}
	if sessionCount == 0 {
		t.Fatal("expected the registration session to be persisted")
	}
	if !sawHash {
		t.Fatal("expected token_hash to be exactly security.HashToken of the issued token")
	}

	var recoveryHash string
	if err := raw.QueryRow(
		`SELECT recovery_code_hash FROM accounts WHERE id = ?`,
		registered.AccountID,
	).Scan(&recoveryHash); err != nil {
		t.Fatalf("read recovery_code_hash: %v", err)
	}
	if recoveryHash == registered.RecoveryCode {
		t.Fatal("recovery code persisted in plaintext")
	}
	if !strings.HasPrefix(recoveryHash, "$2") {
		t.Fatalf("expected a bcrypt hash, got %q prefix", recoveryHash[:min(4, len(recoveryHash))])
	}
	if err := security.CompareRecoveryCodeHash(recoveryHash, registered.RecoveryCode); err != nil {
		t.Fatalf("stored hash does not verify the issued recovery code: %v", err)
	}
}

// TestLoginNeverReturnsSessionTokenAlongsideTOTPChallenge pins both
// directions of the mutual exclusion (formerly a planned regression in
// SECURITY.md): a plain account gets a session and no challenge object, a
// TOTP-enabled account gets a challenge and an empty session field — never
// both in one response.
func TestLoginNeverReturnsSessionTokenAlongsideTOTPChallenge(t *testing.T) {
	type loginShape struct {
		SessionToken  string `json:"session_token"`
		TOTPChallenge *struct {
			ChallengeID string `json:"challenge_id"`
		} `json:"totp_challenge"`
	}

	t.Run("plain account: session, no challenge", func(t *testing.T) {
		handler := newTestServer(t)
		registerOwner(t, handler)

		response := performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/login",
			map[string]string{
				"login":    "owner@example.com",
				"password": "correct horse battery staple",
			},
			"",
			http.StatusOK,
		)
		var body loginShape
		decodeResponse(t, response.Body.Bytes(), &body)
		if body.SessionToken == "" {
			t.Fatal("expected a session token for a plain account")
		}
		if body.TOTPChallenge != nil {
			t.Fatal("expected no totp_challenge alongside a session token")
		}
	})

	t.Run("totp account: challenge, no session", func(t *testing.T) {
		handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
		token := registerOwnerWithTOTP(t, handler)

		enrollResp := performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/totp/enroll",
			map[string]string{"current_password": totpTestPassword},
			token,
			http.StatusOK,
		)
		var enrollBody struct {
			SecretBase32 string `json:"secret_base32"`
		}
		decodeResponse(t, enrollResp.Body.Bytes(), &enrollBody)
		secret, err := security.DecodeTOTPSecretBase32(enrollBody.SecretBase32)
		if err != nil {
			t.Fatalf("decode secret: %v", err)
		}
		performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/totp/verify",
			map[string]string{"code": security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)},
			token,
			http.StatusOK,
		)

		response := performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/login",
			map[string]string{
				"login":    "owner@example.com",
				"password": totpTestPassword,
			},
			"",
			http.StatusOK,
		)
		var body loginShape
		decodeResponse(t, response.Body.Bytes(), &body)
		if body.TOTPChallenge == nil || body.TOTPChallenge.ChallengeID == "" {
			t.Fatal("expected a totp_challenge for a TOTP-enabled account")
		}
		if body.SessionToken != "" {
			t.Fatal("expected no session token alongside a totp_challenge")
		}
	})
}

// TestAuthEndpointJSONBodyCeilingIsEnforced pins the documented 4 KiB auth
// body cap from both sides (formerly a planned regression in SECURITY.md):
// an oversized body is rejected as invalid_json, while a body under the cap
// reaches the credential check.
func TestAuthEndpointJSONBodyCeilingIsEnforced(t *testing.T) {
	handler := newTestServer(t)

	oversized := map[string]string{
		"login":    "owner@example.com",
		"password": strings.Repeat("a", 4<<10),
	}
	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		oversized,
		"",
		http.StatusBadRequest,
	)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_json" {
		t.Fatalf("expected invalid_json for an oversized body, got %#v", payload)
	}

	// Under the cap the same request parses and fails on credentials instead
	// — proving the ceiling sits at the documented limit, not lower.
	fitting := map[string]string{
		"login":    "owner@example.com",
		"password": strings.Repeat("a", 2<<10),
	}
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		fitting,
		"",
		http.StatusUnauthorized,
	)
}

// TestPremiumActiveIsUntouchableThroughPublicEndpoints pins the bridge-only
// write path for premium_active (formerly a planned regression in
// SECURITY.md): after the ordinary public flows the flag is still 0 on disk,
// and the bridge premium route refuses a session bearer outright.
func TestPremiumActiveIsUntouchableThroughPublicEndpoints(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})
	registered := registerOwner(t, handler)

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registered.SessionToken,
		http.StatusOK,
	)

	// A session bearer is not the bridge credential: constant-time compare
	// fails and the premium route stays unauthorized.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+registered.AccountID+"/premium",
		map[string]any{"active": true},
		registered.SessionToken,
		http.StatusUnauthorized,
	)

	raw := openRawReadConnection(t, dbPath)
	var premiumActive int
	if err := raw.QueryRow(
		`SELECT premium_active FROM accounts WHERE id = ?`,
		registered.AccountID,
	).Scan(&premiumActive); err != nil {
		t.Fatalf("read premium_active: %v", err)
	}
	if premiumActive != 0 {
		t.Fatalf("expected premium_active to stay 0 for a self-hosted account, got %d", premiumActive)
	}
}
