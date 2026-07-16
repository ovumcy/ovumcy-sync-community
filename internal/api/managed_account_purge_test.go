package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

// provisionManagedAccountWithData creates a managed-bridge account over HTTP
// and fills it with a device, a recovery-key package, and an encrypted blob,
// returning the bridge-issued session token. It exercises the same routes a
// real managed client uses so the purge tests erase realistically-shaped data.
func provisionManagedAccountWithData(t *testing.T, handler http.Handler, accountID string) string {
	t.Helper()

	sessionResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{"account_id": accountID},
		"test-managed-bridge-token",
		http.StatusOK,
	)
	var sessionPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, sessionResponse.Body.Bytes(), &sessionPayload)
	if sessionPayload.SessionToken == "" {
		t.Fatal("expected managed bridge session token")
	}

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-1aaaa",
			"device_label": "Pixel 7",
		},
		sessionPayload.SessionToken,
		http.StatusOK,
	)

	performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/recovery-key",
		map[string]any{
			"algorithm":              "xchacha20poly1305",
			"kdf":                    "bip39_seed_hkdf_sha256",
			"mnemonic_word_count":    12,
			"wrap_nonce_hex":         strings.Repeat("a", 48),
			"wrapped_master_key_hex": strings.Repeat("b", 96),
			"phrase_fingerprint_hex": strings.Repeat("c", 16),
		},
		sessionPayload.SessionToken,
		http.StatusOK,
	)

	checksumBytes := sha256.Sum256([]byte("managed-ciphertext"))
	performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		map[string]any{
			"schema_version":    1,
			"generation":        1,
			"checksum_sha256":   hex.EncodeToString(checksumBytes[:]),
			"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("managed-ciphertext")),
		},
		sessionPayload.SessionToken,
		http.StatusOK,
	)

	return sessionPayload.SessionToken
}

func TestServerRejectsManagedAccountPurgeWhenDisabled(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		disableManaged: true,
	})

	response := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/managed/accounts/managedacct1234",
		nil,
		"test-managed-bridge-token",
		http.StatusServiceUnavailable,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "managed_bridge_disabled" {
		t.Fatalf("unexpected managed bridge disabled payload: %#v", payload)
	}
}

func TestServerManagedAccountPurgeRejectsWrongBridgeToken(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/managed/accounts/managedacct1234",
		nil,
		"wrong-bridge-token",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "unauthorized" {
		t.Fatalf("unexpected managed bridge auth payload: %#v", payload)
	}

	// A request with no bearer at all is refused the same way.
	performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/managed/accounts/managedacct1234",
		nil,
		"",
		http.StatusUnauthorized,
	)
}

func TestServerManagedAccountPurgeCascades(t *testing.T) {
	store := newTestStore(t, ":memory:")
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})

	const accountID = "managedacct1234"
	sessionToken := provisionManagedAccountWithData(t, handler, accountID)

	purgeResponse := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/managed/accounts/"+accountID,
		nil,
		"test-managed-bridge-token",
		http.StatusOK,
	)
	var purgePayload map[string]string
	decodeResponse(t, purgeResponse.Body.Bytes(), &purgePayload)
	if purgePayload["status"] != "account_purged" {
		t.Fatalf("unexpected purge payload: %#v", purgePayload)
	}

	// The bridge-issued session no longer authenticates: its account is gone.
	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		sessionToken,
		http.StatusUnauthorized,
	)

	// Persistence-level proof of the cascade: the ciphertext blob — the
	// special-category payload this purge exists for — plus the recovery-key
	// package, devices, and the account row itself are all gone.
	ctx := context.Background()
	if _, err := store.GetEncryptedBlob(ctx, accountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected encrypted blob gone after purge, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, accountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected recovery key package gone after purge, got %v", err)
	}
	if count, err := store.CountDevicesForAccount(ctx, accountID); err != nil || count != 0 {
		t.Fatalf("expected zero devices after purge, got count=%d err=%v", count, err)
	}
	if _, err := store.FindAccountByID(ctx, accountID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected account row gone after purge, got %v", err)
	}
}

func TestServerManagedAccountPurgeIsIdempotent(t *testing.T) {
	handler := newTestServer(t)

	const accountID = "managedacct1234"
	provisionManagedAccountWithData(t, handler, accountID)

	for attempt := range 2 {
		response := performJSONRequest(
			t,
			handler,
			http.MethodDelete,
			"/managed/accounts/"+accountID,
			nil,
			"test-managed-bridge-token",
			http.StatusOK,
		)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["status"] != "account_purged" {
			t.Fatalf("unexpected purge payload on call %d: %#v", attempt+1, payload)
		}
	}

	// A managed account id that never existed also reports success, so a
	// managed caller retrying after a dropped response converges either way.
	performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/managed/accounts/neverexisted1234",
		nil,
		"test-managed-bridge-token",
		http.StatusOK,
	)
}

func TestServerManagedAccountPurgeRefusesSelfHostedAccount(t *testing.T) {
	handler := newTestServer(t)

	registered := registerOwner(t, handler)

	checksumBytes := sha256.Sum256([]byte("self-hosted-ciphertext"))
	performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		map[string]any{
			"schema_version":    1,
			"generation":        1,
			"checksum_sha256":   hex.EncodeToString(checksumBytes[:]),
			"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("self-hosted-ciphertext")),
		},
		registered.SessionToken,
		http.StatusOK,
	)

	// The bridge credential must never erase a self-hosted account, even when
	// handed that account's real id.
	response := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/managed/accounts/"+registered.AccountID,
		nil,
		"test-managed-bridge-token",
		http.StatusBadRequest,
	)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_managed_account" {
		t.Fatalf("unexpected refusal payload: %#v", payload)
	}

	// The self-hosted account is untouched: its session still authenticates
	// and its blob is still served.
	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registered.SessionToken,
		http.StatusOK,
	)
	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/blob",
		nil,
		registered.SessionToken,
		http.StatusOK,
	)
}
