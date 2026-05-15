package api

import (
	"net/http"
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
