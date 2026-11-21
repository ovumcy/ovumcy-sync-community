package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// enrollTOTPForLogin registers login from its own address, enrolls and
// verifies TOTP with the current step's code, and returns the secret plus the
// verified step so a later challenge can answer with a step not yet claimed.
func enrollTOTPForLogin(t *testing.T, handler http.Handler, login string, remoteAddr string) ([]byte, int64) {
	t.Helper()

	token := registerAccountFrom(t, handler, login, remoteAddr)
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
	return secret, step
}

func loginForChallengeAs(t *testing.T, handler http.Handler, login string) string {
	t.Helper()

	resp := performJSONRequest(t, handler, http.MethodPost, "/auth/login",
		map[string]string{"login": login, "password": totpTestPassword}, "", http.StatusOK)
	var body struct {
		SessionToken  string `json:"session_token"`
		TOTPChallenge *struct {
			ChallengeID string `json:"challenge_id"`
		} `json:"totp_challenge"`
	}
	decodeResponse(t, resp.Body.Bytes(), &body)
	if body.SessionToken != "" || body.TOTPChallenge == nil || body.TOTPChallenge.ChallengeID == "" {
		t.Fatalf("expected a totp challenge and no session token, got %#v", body)
	}
	return body.TOTPChallenge.ChallengeID
}

// TestMFASignInsDoNotSpendThePerIPBudget: with a per-IP budget of one, MFA
// sign-ins of several accounts behind one address all complete, because the
// login refunds its per-IP slot on challenge issuance and the challenge route
// refunds its own on success. A wrong password and a wrong code stay charged.
func TestMFASignInsDoNotSpendThePerIPBudget(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		enableTOTP:          true,
		authRateLimitCount:  1,
		authRateLimitWindow: 15 * time.Minute,
	})

	const accounts = 3
	for i := range accounts {
		login := fmt.Sprintf("mfa-%d@example.com", i)
		secret, step := enrollTOTPForLogin(t, handler, login, fmt.Sprintf("198.51.100.%d:4000", i+1))
		challengeID := loginForChallengeAs(t, handler, login)
		resp := performJSONRequest(t, handler, http.MethodPost, "/auth/totp/challenge",
			map[string]string{"challenge_id": challengeID, "code": security.GenerateTOTPCode(secret, step+1)},
			"", http.StatusOK)
		var body struct {
			SessionToken string `json:"session_token"`
		}
		decodeResponse(t, resp.Body.Bytes(), &body)
		if body.SessionToken == "" {
			t.Fatalf("account %d: expected a session token from the completed challenge", i)
		}
	}

	// Each login above spent its own identifier slot, so the failure checks
	// use logins whose identifier buckets are still fresh: a 429 here can
	// only come from the per-IP bucket.
	enrollTOTPForLogin(t, handler, "mfa-fail@example.com", "198.51.100.100:4000")
	challengeID := loginForChallengeAs(t, handler, "mfa-fail@example.com")
	performJSONRequest(t, handler, http.MethodPost, "/auth/totp/challenge",
		map[string]string{"challenge_id": challengeID, "code": "not-a-code"}, "", http.StatusUnauthorized)
	performJSONRequest(t, handler, http.MethodPost, "/auth/totp/challenge",
		map[string]string{"challenge_id": challengeID, "code": "not-a-code"}, "", http.StatusTooManyRequests)

	performJSONRequest(t, handler, http.MethodPost, "/auth/login",
		map[string]string{"login": "someone@example.com", "password": "wrong-password-1"}, "", http.StatusUnauthorized)
	performJSONRequest(t, handler, http.MethodPost, "/auth/login",
		map[string]string{"login": "someone-else@example.com", "password": totpTestPassword}, "", http.StatusTooManyRequests)
}

// TestMFALoginKeepsTheIdentifierSlotCharged: refunding the per-IP slot on
// challenge issuance leaves the identifier slot charged, so a stolen password
// still cannot mint challenges for one login past the identifier ceiling.
func TestMFALoginKeepsTheIdentifierSlotCharged(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		enableTOTP:          true,
		authRateLimitCount:  2,
		authRateLimitWindow: 15 * time.Minute,
	})
	enrollTOTPForLogin(t, handler, "mfa@example.com", "198.51.100.1:4000")

	loginForChallengeAs(t, handler, "mfa@example.com")
	loginForChallengeAs(t, handler, "mfa@example.com")
	performJSONRequest(t, handler, http.MethodPost, "/auth/login",
		map[string]string{"login": "mfa@example.com", "password": totpTestPassword}, "", http.StatusTooManyRequests)
}
