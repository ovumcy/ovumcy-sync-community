package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

const totpTestPassword = "correct horse battery staple"

func registerOwnerWithTOTP(t *testing.T, handler http.Handler) (sessionToken string) {
	t.Helper()

	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": totpTestPassword,
		},
		"",
		http.StatusCreated,
	)
	var body struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body.SessionToken == "" {
		t.Fatal("expected session token")
	}
	return body.SessionToken
}

func TestTOTPNotConfiguredWhenServerHasNoFieldKey(t *testing.T) {
	handler := newTestServer(t)
	token := registerOwnerWithTOTP(t, handler)

	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/enroll",
		map[string]string{"current_password": totpTestPassword},
		token,
		http.StatusServiceUnavailable,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_not_configured" {
		t.Fatalf("unexpected error: %#v", body)
	}
}

func TestTOTPEnrollVerifyDisableEndToEnd(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token := registerOwnerWithTOTP(t, handler)

	// 1) StartEnrollment with wrong password fails.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/enroll",
		map[string]string{"current_password": "wrong"},
		token,
		http.StatusUnauthorized,
	)

	// 2) StartEnrollment with right password returns secret + URI.
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
		SecretBase32    string `json:"secret_base32"`
		ProvisioningURI string `json:"provisioning_uri"`
	}
	decodeResponse(t, enrollResp.Body.Bytes(), &enrollBody)
	if enrollBody.SecretBase32 == "" || enrollBody.ProvisioningURI == "" {
		t.Fatalf("incomplete enrollment response: %#v", enrollBody)
	}

	secret, err := security.DecodeTOTPSecretBase32(enrollBody.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}

	// 3) Verify with wrong code fails.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": "000000"},
		token,
		http.StatusUnauthorized,
	)

	// 4) Verify with the right code succeeds.
	goodCode := security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": goodCode},
		token,
		http.StatusOK,
	)

	// 5) Login now returns a TOTP challenge, not a session.
	loginResp := performJSONRequest(
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
	var loginBody struct {
		SessionToken  string `json:"session_token"`
		TOTPChallenge *struct {
			ChallengeID        string `json:"challenge_id"`
			ChallengeExpiresAt string `json:"challenge_expires_at"`
		} `json:"totp_challenge"`
	}
	decodeResponse(t, loginResp.Body.Bytes(), &loginBody)
	if loginBody.SessionToken != "" {
		t.Fatalf("expected empty session token on 2FA login, got %q", loginBody.SessionToken)
	}
	if loginBody.TOTPChallenge == nil || loginBody.TOTPChallenge.ChallengeID == "" {
		t.Fatalf("expected totp challenge id, got %#v", loginBody.TOTPChallenge)
	}

	// 6) Wait for a fresh step so we don't replay the verify step.
	for {
		nextCode := security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)
		if nextCode != goodCode {
			goodCode = nextCode
			break
		}
		time.Sleep(time.Second)
	}

	// 7) Challenge with wrong code fails.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": loginBody.TOTPChallenge.ChallengeID,
			"code":         "000000",
		},
		"",
		http.StatusUnauthorized,
	)

	// 8) Challenge with right code returns a real session.
	challengeResp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": loginBody.TOTPChallenge.ChallengeID,
			"code":         goodCode,
		},
		"",
		http.StatusOK,
	)
	var challengeBody struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, challengeResp.Body.Bytes(), &challengeBody)
	if challengeBody.SessionToken == "" {
		t.Fatal("expected session token from completed challenge")
	}

	// 9) Reusing the challenge id fails.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": loginBody.TOTPChallenge.ChallengeID,
			"code":         goodCode,
		},
		"",
		http.StatusUnauthorized,
	)

	// 10) Disable with wrong code fails.
	for {
		nextCode := security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)
		if nextCode != goodCode {
			goodCode = nextCode
			break
		}
		time.Sleep(time.Second)
	}
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/disable",
		map[string]string{
			"current_password": totpTestPassword,
			"code":             "000000",
		},
		token,
		http.StatusUnauthorized,
	)

	// 11) Disable with correct password + code succeeds.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/disable",
		map[string]string{
			"current_password": totpTestPassword,
			"code":             goodCode,
		},
		token,
		http.StatusOK,
	)

	// 12) Login now returns a regular session (no TOTP challenge).
	relogResp := performJSONRequest(
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
	var relogBody struct {
		SessionToken  string `json:"session_token"`
		TOTPChallenge *struct{} `json:"totp_challenge"`
	}
	decodeResponse(t, relogResp.Body.Bytes(), &relogBody)
	if relogBody.SessionToken == "" {
		t.Fatal("expected ordinary session after disable")
	}
	if relogBody.TOTPChallenge != nil {
		t.Fatal("expected no totp_challenge after disable")
	}
}

func TestTOTPEnrollRejectsWhenAlreadyEnabled(t *testing.T) {
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
	secret, _ := security.DecodeTOTPSecretBase32(enrollBody.SecretBase32)

	code := security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": code},
		token,
		http.StatusOK,
	)

	// Second enroll attempt while already enabled is a conflict.
	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/enroll",
		map[string]string{"current_password": totpTestPassword},
		token,
		http.StatusConflict,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_already_enabled" {
		t.Fatalf("unexpected error key: %#v", body)
	}
}

func TestTOTPChallengeWithInvalidIDReturnsGenericError(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})

	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": "not-a-real-challenge",
			"code":         "000000",
		},
		"",
		http.StatusUnauthorized,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_challenge_invalid" {
		t.Fatalf("unexpected error key: %#v", body)
	}
}

func TestTOTPChallengeBurnsAfterFiveWrongCodes(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token := registerOwnerWithTOTP(t, handler)

	// Enroll TOTP so login goes through the challenge path.
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
	code := security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": code},
		token,
		http.StatusOK,
	)

	// Trigger a login challenge.
	loginResp := performJSONRequest(
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
	var loginBody struct {
		TOTPChallenge *struct {
			ChallengeID string `json:"challenge_id"`
		} `json:"totp_challenge"`
	}
	decodeResponse(t, loginResp.Body.Bytes(), &loginBody)
	if loginBody.TOTPChallenge == nil {
		t.Fatalf("expected totp challenge, got %#v", loginBody)
	}
	challengeID := loginBody.TOTPChallenge.ChallengeID

	// First four wrong attempts must stay retryable (totp_invalid_code).
	for i := range 4 {
		resp := performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/totp/challenge",
			map[string]string{
				"challenge_id": challengeID,
				"code":         "000000",
			},
			"",
			http.StatusUnauthorized,
		)
		var body map[string]string
		decodeResponse(t, resp.Body.Bytes(), &body)
		if body["error"] != "totp_invalid_code" {
			t.Fatalf("attempt %d: expected totp_invalid_code, got %#v", i+1, body)
		}
	}

	// Fifth wrong attempt burns the challenge.
	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": challengeID,
			"code":         "000000",
		},
		"",
		http.StatusUnauthorized,
	)
	var burnBody map[string]string
	decodeResponse(t, resp.Body.Bytes(), &burnBody)
	if burnBody["error"] != "totp_challenge_invalid" {
		t.Fatalf("expected totp_challenge_invalid on burn, got %#v", burnBody)
	}

	// Even the correct code does not bring it back — the challenge is gone.
	correctCode := security.GenerateTOTPCode(
		secret,
		time.Now().Unix()/security.TOTPStepSeconds,
	)
	resp = performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": challengeID,
			"code":         correctCode,
		},
		"",
		http.StatusUnauthorized,
	)
	var afterBody map[string]string
	decodeResponse(t, resp.Body.Bytes(), &afterBody)
	if afterBody["error"] != "totp_challenge_invalid" {
		t.Fatalf("expected challenge to stay burnt, got %#v", afterBody)
	}
}

func TestTOTPMetricsExposeChallengeAndEnrollmentResults(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		enableTOTP:    true,
		enableMetrics: true,
	})
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

	// One invalid_code enrollment outcome.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": "000000"},
		token,
		http.StatusUnauthorized,
	)
	// One ok enrollment outcome.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)},
		token,
		http.StatusOK,
	)

	// Trigger a login challenge and burn it through 5 wrong attempts.
	loginResp := performJSONRequest(
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
	var loginBody struct {
		TOTPChallenge *struct {
			ChallengeID string `json:"challenge_id"`
		} `json:"totp_challenge"`
	}
	decodeResponse(t, loginResp.Body.Bytes(), &loginBody)
	if loginBody.TOTPChallenge == nil {
		t.Fatalf("expected challenge, got %#v", loginBody)
	}
	for range 5 {
		performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/totp/challenge",
			map[string]string{
				"challenge_id": loginBody.TOTPChallenge.ChallengeID,
				"code":         "000000",
			},
			"",
			http.StatusUnauthorized,
		)
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status %d, body=%s", recorder.Code, recorder.Body.String())
	}
	payload := recorder.Body.String()

	for _, expected := range []string{
		`ovumcy_sync_community_totp_enrollment_completion_total{result="invalid_code"} 1`,
		`ovumcy_sync_community_totp_enrollment_completion_total{result="ok"} 1`,
		`ovumcy_sync_community_totp_challenge_completion_total{result="invalid_code"} 4`,
		`ovumcy_sync_community_totp_challenge_completion_total{result="burnt"} 1`,
	} {
		if !strings.Contains(payload, expected) {
			t.Fatalf("missing metric line %q in payload:\n%s", expected, payload)
		}
	}
}

func TestTOTPVerifyWithoutPendingEnrollmentReturnsNotConfigured(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token := registerOwnerWithTOTP(t, handler)

	// No StartEnrollment happened, so there is no stashed secret to verify
	// against; the endpoint reports the not-configured state instead of a
	// misleading invalid-code error.
	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": "000000"},
		token,
		http.StatusServiceUnavailable,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_not_configured" {
		t.Fatalf("unexpected verify-without-enrollment payload: %#v", body)
	}
}

func TestTOTPDisableWhenNotEnabledReturnsNotConfigured(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token := registerOwnerWithTOTP(t, handler)

	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/disable",
		map[string]string{
			"current_password": totpTestPassword,
			"code":             "000000",
		},
		token,
		http.StatusServiceUnavailable,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_not_configured" {
		t.Fatalf("unexpected disable-when-not-enabled payload: %#v", body)
	}
}

func TestTOTPChallengeRejectsReplayedCode(t *testing.T) {
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

	enrollmentCode := security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": enrollmentCode},
		token,
		http.StatusOK,
	)

	// Wait for a step the enrollment verify has not touched, so this test
	// pins challenge-vs-challenge replay only.
	code := enrollmentCode
	for {
		nextCode := security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)
		if nextCode != code {
			code = nextCode
			break
		}
		time.Sleep(time.Second)
	}

	// First login challenge: the fresh code is accepted and claims its step.
	firstChallengeID := loginForTOTPChallengeID(t, handler)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": firstChallengeID,
			"code":         code,
		},
		"",
		http.StatusOK,
	)

	// Second login challenge, same code: the step was already consumed, so
	// the replay must be refused even though the code is still current.
	secondChallengeID := loginForTOTPChallengeID(t, handler)
	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": secondChallengeID,
			"code":         code,
		},
		"",
		http.StatusUnauthorized,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_replayed" {
		t.Fatalf("unexpected replayed-code payload: %#v", body)
	}
}

// loginForTOTPChallengeID performs a password login for the TOTP-enabled test
// owner and returns the issued challenge id, asserting the mutually exclusive
// response shape: a TOTP challenge and never a session token alongside it.
func loginForTOTPChallengeID(t *testing.T, handler http.Handler) string {
	t.Helper()

	resp := performJSONRequest(
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
	var body struct {
		SessionToken  string `json:"session_token"`
		TOTPChallenge *struct {
			ChallengeID string `json:"challenge_id"`
		} `json:"totp_challenge"`
	}
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body.SessionToken != "" {
		t.Fatalf("expected no session token alongside a totp challenge, got %q", body.SessionToken)
	}
	if body.TOTPChallenge == nil || body.TOTPChallenge.ChallengeID == "" {
		t.Fatalf("expected totp challenge id, got %#v", body.TOTPChallenge)
	}
	return body.TOTPChallenge.ChallengeID
}

func TestTOTPVerifyAcrossFieldKeyMismatchReturnsSecretFailed(t *testing.T) {
	store := newTestStore(t, ":memory:")

	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	for i := range keyA {
		keyA[i] = byte(i + 1)
		keyB[i] = byte(i + 101)
	}

	serverA := newTestServerWithOptions(t, serverTestOptions{
		store:      store,
		enableTOTP: true,
		totpKey:    keyA,
	})
	serverB := newTestServerWithOptions(t, serverTestOptions{
		store:      store,
		enableTOTP: true,
		totpKey:    keyB,
	})

	token := registerOwnerWithTOTP(t, serverA)
	performJSONRequest(
		t,
		serverA,
		http.MethodPost,
		"/auth/totp/enroll",
		map[string]string{"current_password": totpTestPassword},
		token,
		http.StatusOK,
	)

	// The pending secret was encrypted under server A's key; a server holding
	// a different field key cannot decrypt it and must fail loudly instead of
	// accepting or misreporting the code.
	resp := performJSONRequest(
		t,
		serverB,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": "000000"},
		token,
		http.StatusInternalServerError,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_secret_failed" {
		t.Fatalf("unexpected key-mismatch payload: %#v", body)
	}
}

func TestLoginFailsClosedWhenTOTPEnabledButServerHasNoFieldKey(t *testing.T) {
	store := newTestStore(t, ":memory:")

	serverWithTOTP := newTestServerWithOptions(t, serverTestOptions{
		store:      store,
		enableTOTP: true,
	})
	serverWithoutTOTP := newTestServerWithOptions(t, serverTestOptions{
		store: store,
	})

	token := registerOwnerWithTOTP(t, serverWithTOTP)
	enrollResp := performJSONRequest(
		t,
		serverWithTOTP,
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
		serverWithTOTP,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": security.GenerateTOTPCode(secret, time.Now().Unix()/security.TOTPStepSeconds)},
		token,
		http.StatusOK,
	)

	// The same account against a server with no TOTP capability (no field
	// encryption key): the login must fail closed with 503 rather than
	// silently downgrading an enrolled account to password-only auth.
	resp := performJSONRequest(
		t,
		serverWithoutTOTP,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": totpTestPassword,
		},
		"",
		http.StatusServiceUnavailable,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "totp_not_configured" {
		t.Fatalf("unexpected fail-closed login payload: %#v", body)
	}
}

func TestTOTPChallengeReturnsInternalErrorWhenStoreFails(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{
		store:      store,
		enableTOTP: true,
	})

	dropTable(t, dbPath, "totp_challenges")

	resp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/challenge",
		map[string]string{
			"challenge_id": "any-challenge-id",
			"code":         "000000",
		},
		"",
		http.StatusInternalServerError,
	)
	var body map[string]string
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body["error"] != "internal_error" {
		t.Fatalf("unexpected challenge store failure payload: %#v", body)
	}
}
