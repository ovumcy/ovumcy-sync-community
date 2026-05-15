package api

import (
	"net/http"
	"testing"
)

func TestChangePasswordEndpointSucceedsAndRevokesOtherSessions(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		AccountID    string `json:"account_id"`
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	loginResponse := performJSONRequest(
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

	var loginPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, loginResponse.Body.Bytes(), &loginPayload)

	changeResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/change-password",
		map[string]string{
			"current_password": "correct horse battery staple",
			"new_password":     "new staple battery horse correct",
		},
		registerPayload.SessionToken,
		http.StatusOK,
	)

	var changePayload map[string]string
	decodeResponse(t, changeResponse.Body.Bytes(), &changePayload)
	if changePayload["status"] != "password_changed" {
		t.Fatalf("unexpected change-password payload: %#v", changePayload)
	}

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		loginPayload.SessionToken,
		http.StatusUnauthorized,
	)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusUnauthorized,
	)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": "new staple battery horse correct",
		},
		"",
		http.StatusOK,
	)
}

func TestChangePasswordEndpointRejectsWrongCurrent(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/change-password",
		map[string]string{
			"current_password": "wrong current password",
			"new_password":     "new staple battery horse correct",
		},
		registerPayload.SessionToken,
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_current_password" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestChangePasswordEndpointRejectsSamePassword(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/change-password",
		map[string]string{
			"current_password": "correct horse battery staple",
			"new_password":     "correct horse battery staple",
		},
		registerPayload.SessionToken,
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "new_password_must_differ" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestChangePasswordEndpointRejectsWeakNew(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/change-password",
		map[string]string{
			"current_password": "correct horse battery staple",
			"new_password":     "short",
		},
		registerPayload.SessionToken,
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "weak_new_password" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestChangePasswordEndpointRequiresAuth(t *testing.T) {
	handler := newTestServer(t)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/change-password",
		map[string]string{
			"current_password": "correct horse battery staple",
			"new_password":     "new staple battery horse correct",
		},
		"",
		http.StatusUnauthorized,
	)
}
