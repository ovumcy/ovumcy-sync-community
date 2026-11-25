package api

import (
	"net/http"
	"testing"
)

func loginSessionToken(t *testing.T, handler http.Handler, login string) string {
	t.Helper()
	response := performJSONRequest(t, handler, http.MethodPost, "/auth/login",
		map[string]string{"login": login, "password": "correct horse battery staple"}, "", http.StatusOK)
	var body struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, response.Body.Bytes(), &body)
	if body.SessionToken == "" {
		t.Fatal("expected a session token from login")
	}
	return body.SessionToken
}

// A login past the per-account session ceiling revokes that account's
// oldest session — its token answers 401 from then on — and leaves the
// account's newer sessions and every other account's sessions working.
func TestLoginPastMaxSessionsRevokesTheOldestSession(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{maxSessions: 2})

	other := performJSONRequest(t, handler, http.MethodPost, "/auth/register",
		map[string]string{"login": "other@example.com", "password": "correct horse battery staple"}, "", http.StatusCreated)
	var otherBody struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, other.Body.Bytes(), &otherBody)
	otherSecond := loginSessionToken(t, handler, "other@example.com")

	oldest := registerOwner(t, handler).SessionToken
	second := loginSessionToken(t, handler, "owner@example.com")
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, oldest, http.StatusOK)

	newest := loginSessionToken(t, handler, "owner@example.com")

	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, oldest, http.StatusUnauthorized)
	for _, token := range []string{second, newest, otherBody.SessionToken, otherSecond} {
		performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, token, http.StatusOK)
	}
}
