package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// TestTOTPChallengeLocksTheAccountAcrossLogins drives the SYNC-4 attack over
// HTTP: logging in again mints a fresh challenge, but the eleventh wrong code
// in the window answers 429 `rate_limited` with a Retry-After inside the
// 15-minute window instead of another retryable 401.
func TestTOTPChallengeLocksTheAccountAcrossLogins(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true, authRateLimitCount: 100})
	token := registerOwnerWithTOTP(t, handler)

	enrollResp := performJSONRequest(t, handler, http.MethodPost, "/auth/totp/enroll",
		map[string]string{"current_password": totpTestPassword}, token, http.StatusOK)
	var enrollBody struct {
		SecretBase32 string `json:"secret_base32"`
	}
	decodeResponse(t, enrollResp.Body.Bytes(), &enrollBody)
	secret, err := security.DecodeTOTPSecretBase32(enrollBody.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	step := time.Now().Unix() / security.TOTPStepSeconds
	performJSONRequest(t, handler, http.MethodPost, "/auth/totp/verify",
		map[string]string{"code": security.GenerateTOTPCode(secret, step)}, token, http.StatusOK)

	// Valid codes span two adjacent windows in case the test straddles a step.
	valid := map[string]bool{}
	for s := step - 2; s <= step+3; s++ {
		valid[security.GenerateTOTPCode(secret, s)] = true
	}
	wrong := ""
	for _, candidate := range []string{"000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777"} {
		if !valid[candidate] {
			wrong = candidate
			break
		}
	}

	for range 2 {
		challengeID := loginForTOTPChallengeID(t, handler)
		for range 5 {
			performJSONRequest(t, handler, http.MethodPost, "/auth/totp/challenge",
				map[string]string{"challenge_id": challengeID, "code": wrong}, "", http.StatusUnauthorized)
		}
	}

	resp := performJSONRequest(t, handler, http.MethodPost, "/auth/totp/challenge",
		map[string]string{"challenge_id": loginForTOTPChallengeID(t, handler), "code": wrong}, "", http.StatusTooManyRequests)
	var body struct {
		Error string `json:"error"`
	}
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body.Error != "rate_limited" {
		t.Fatalf("error key = %q, want rate_limited", body.Error)
	}
	retryAfter, err := strconv.Atoi(resp.Header().Get("Retry-After"))
	if err != nil || retryAfter < 1 || retryAfter > int((15*time.Minute).Seconds()) {
		t.Fatalf("Retry-After = %q, want 1..900 seconds", resp.Header().Get("Retry-After"))
	}
}
