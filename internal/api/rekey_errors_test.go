package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServerPutRekeyRefusalKeys(t *testing.T) {
	handler := newTestServer(t)
	token := registerOwner(t, handler).SessionToken
	password := map[string]string{"current_password": "correct horse battery staple"}
	k1 := strings.Repeat("c", 16)

	badCiphertext := rekeyBody(k1, 1, "k1", 0, password)
	badCiphertext["blob"].(map[string]any)["ciphertext_base64"] = "not base64!"
	response := performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", badCiphertext, token, http.StatusBadRequest)
	expectErrorKey(t, response.Body.Bytes(), "invalid_ciphertext")

	badPackage := rekeyBody(k1, 1, "k1", 0, password)
	badPackage["recovery_key"].(map[string]any)["algorithm"] = "rot13"
	response = performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", badPackage, token, http.StatusBadRequest)
	expectErrorKey(t, response.Body.Bytes(), "invalid_recovery_package")

	performJSONRequest(t, handler, http.MethodGet, "/sync/recovery-key", nil, token, http.StatusNotFound)
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, token, http.StatusNotFound)
}

func TestServerPutRekeyManagedAccountCannotReplaceItsPackage(t *testing.T) {
	handler := newTestServer(t)
	sessionResponse := performJSONRequest(t, handler, http.MethodPost, "/managed/session",
		map[string]string{"account_id": "managedacct9013"}, "test-managed-bridge-token", http.StatusOK)
	var session struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, sessionResponse.Body.Bytes(), &session)
	base := time.Now().UTC().UnixMilli()

	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey",
		rekeyBody(strings.Repeat("c", 16), base, "k1", 0, nil), session.SessionToken, http.StatusOK)
	response := performJSONRequest(t, handler, http.MethodPut, "/sync/rekey",
		rekeyBody(strings.Repeat("d", 16), base+1, "k2", base, nil), session.SessionToken, http.StatusForbidden)
	expectErrorKey(t, response.Body.Bytes(), "managed_recovery_key_overwrite")
}

func TestServerPutRekeyStoreFailureIsInternal(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})
	token := registerOwner(t, handler).SessionToken

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000; DROP TABLE recovery_key_packages`); err != nil {
		t.Fatalf("drop recovery_key_packages: %v", err)
	}

	response := performJSONRequest(t, handler, http.MethodPut, "/sync/rekey",
		rekeyBody(strings.Repeat("c", 16), 1, "k1", 0, map[string]string{"current_password": "correct horse battery staple"}),
		token, http.StatusInternalServerError)
	expectErrorKey(t, response.Body.Bytes(), "internal_error")
}

// A re-key waiting for a blob slot ends with its client and reads nothing.
func TestServerPutRekeyWaitingForASlotEndsWithItsClient(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{syncRateLimitCount: 100})
	token := registerForBlobTest(t, handler, "owner@example.com")
	held := holdEveryBlobSlot(t, handler, blobPutPayload(t))

	ctx, cancel := context.WithCancel(context.Background())
	body := newGatedBody(t, []byte(`{}`))
	request := httptest.NewRequestWithContext(ctx, http.MethodPut, "/sync/rekey", body)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}()
	time.Sleep(blobSlotSilence)
	cancel()
	select {
	case <-done:
	case <-time.After(blobSlotWait):
		t.Fatal("a waiting re-key outlived its client")
	}
	select {
	case <-body.started:
		t.Fatal("a re-key read its body without a slot")
	default:
	}

	for _, transfer := range held {
		transfer.body.release()
		<-transfer.done
	}
}
