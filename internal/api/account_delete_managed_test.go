package api

import (
	"context"
	"net/http"
	"testing"
)

// A managed session cannot erase its account through DELETE /account — it has
// no password to re-check, so a stolen one would be enough. The refusal leaves
// the account, its data and the session intact; the bridge purge stays the
// only way to delete it.
func TestDeleteAccountEndpointRefusesManagedSession(t *testing.T) {
	store := newTestStore(t, ":memory:")
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})

	const accountID = "managedacct5678"
	sessionToken := provisionManagedAccountWithData(t, handler, accountID)

	for _, body := range []any{
		map[string]string{},
		map[string]string{"current_password": "anything at all"},
	} {
		response := performJSONRequest(
			t,
			handler,
			http.MethodDelete,
			"/account",
			body,
			sessionToken,
			http.StatusForbidden,
		)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "managed_account_delete_via_bridge" {
			t.Fatalf("unexpected refusal payload for %#v: %#v", body, payload)
		}
	}

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		sessionToken,
		http.StatusOK,
	)
	ctx := context.Background()
	if _, err := store.FindAccountByID(ctx, accountID); err != nil {
		t.Fatalf("expected managed account to survive the refused delete, got %v", err)
	}
	if _, err := store.GetEncryptedBlob(ctx, accountID); err != nil {
		t.Fatalf("expected encrypted blob to survive the refused delete, got %v", err)
	}
}
