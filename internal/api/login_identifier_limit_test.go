package api

import (
	"fmt"
	"net/http"
	"testing"
)

const lockoutVictimLogin = "victim@example.com"

func registerLockoutVictim(t *testing.T, handler http.Handler) registerPayload {
	t.Helper()

	response := performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/register",
		body:           map[string]string{"login": lockoutVictimLogin, "password": "correct horse battery staple"},
		remoteAddr:     "198.51.100.200:1000",
		expectedStatus: http.StatusCreated,
	})
	var payload registerPayload
	decodeResponse(t, response.Body.Bytes(), &payload)
	return payload
}

// loginAs sends one login for the victim from its own source address, so the
// per-IP gate never fires and only the identifier bucket is exercised.
func loginAs(t *testing.T, handler http.Handler, sourceIndex int, password string, expectedStatus int) {
	t.Helper()

	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": lockoutVictimLogin, "password": password},
		remoteAddr:     fmt.Sprintf("203.0.113.%d:4000", sourceIndex),
		expectedStatus: expectedStatus,
	})
}

func TestLoginIdentifierBucketChargesOnlyFailures(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 2})
	registerLockoutVictim(t, handler)

	for i := 1; i <= 4; i++ {
		loginAs(t, handler, i, "correct horse battery staple", http.StatusOK)
	}
	loginAs(t, handler, 5, "wrong password", http.StatusUnauthorized)
	loginAs(t, handler, 6, "wrong password", http.StatusUnauthorized)
	loginAs(t, handler, 7, "correct horse battery staple", http.StatusTooManyRequests)
}

func TestForgotPasswordClearsLoginIdentifierLockout(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 2})
	victim := registerLockoutVictim(t, handler)

	loginAs(t, handler, 1, "wrong password", http.StatusUnauthorized)
	loginAs(t, handler, 2, "wrong password", http.StatusUnauthorized)
	loginAs(t, handler, 3, "correct horse battery staple", http.StatusTooManyRequests)

	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/forgot-password",
		body:           map[string]string{"login": lockoutVictimLogin, "recovery_code": victim.RecoveryCode},
		remoteAddr:     "198.51.100.201:1000",
		expectedStatus: http.StatusOK,
	})

	loginAs(t, handler, 4, "correct horse battery staple", http.StatusOK)
}

func TestFailedForgotPasswordKeepsLoginIdentifierLockout(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 2})
	registerLockoutVictim(t, handler)

	loginAs(t, handler, 1, "wrong password", http.StatusUnauthorized)
	loginAs(t, handler, 2, "wrong password", http.StatusUnauthorized)

	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/forgot-password",
		body:           map[string]string{"login": lockoutVictimLogin, "recovery_code": "not-the-recovery-code"},
		remoteAddr:     "198.51.100.201:1000",
		expectedStatus: http.StatusUnauthorized,
	})

	loginAs(t, handler, 3, "correct horse battery staple", http.StatusTooManyRequests)
}
