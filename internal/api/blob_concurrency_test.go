package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// gatedBody reports the handler's first read on started, then blocks the read
// until release — a blob PUT that holds its transfer slot mid-body.
type gatedBody struct {
	once     sync.Once
	openOnce sync.Once
	started  chan struct{}
	open     chan struct{}
	body     *bytes.Reader
}

// newGatedBody releases the body at cleanup, so a failed test leaves no
// handler blocked.
func newGatedBody(t *testing.T, payload []byte) *gatedBody {
	body := &gatedBody{
		started: make(chan struct{}),
		open:    make(chan struct{}),
		body:    bytes.NewReader(payload),
	}
	t.Cleanup(body.release)
	return body
}

func (b *gatedBody) release() {
	b.openOnce.Do(func() { close(b.open) })
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.open
	return b.body.Read(p)
}

func blobPutPayload(t *testing.T) []byte {
	t.Helper()
	checksum := sha256.Sum256([]byte("ciphertext"))
	payload, err := json.Marshal(map[string]any{
		"schema_version":    1,
		"generation":        1,
		"checksum_sha256":   hex.EncodeToString(checksum[:]),
		"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return payload
}

type pendingTransfer struct {
	body     *gatedBody
	response *httptest.ResponseRecorder
	done     chan struct{}
}

func startBlobTransfer(ctx context.Context, handler http.Handler, method, token string, body *gatedBody) *pendingTransfer {
	transfer := &pendingTransfer{body: body, response: httptest.NewRecorder(), done: make(chan struct{})}
	var request *http.Request
	if body != nil {
		request = httptest.NewRequestWithContext(ctx, method, "/sync/blob", body)
		request.Header.Set("Content-Type", "application/json")
	} else {
		request = httptest.NewRequestWithContext(ctx, method, "/sync/blob", nil)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	go func() {
		defer close(transfer.done)
		handler.ServeHTTP(transfer.response, request)
	}()
	return transfer
}

func registerForBlobTest(t *testing.T, handler http.Handler, login string) string {
	t.Helper()
	var registered struct {
		SessionToken string `json:"session_token"`
	}
	response := performJSONRequest(t, handler, http.MethodPost, "/auth/register",
		map[string]string{"login": login, "password": "correct horse battery staple"}, "", http.StatusCreated)
	decodeResponse(t, response.Body.Bytes(), &registered)
	return registered.SessionToken
}

const blobSlotWait = 5 * time.Second

// Silence is checked for a short window only: a transfer that got a slot it
// should not have reads its body within microseconds.
const blobSlotSilence = 200 * time.Millisecond

func TestConcurrentBlobTransfersNeverExceedTheCap(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{syncRateLimitCount: 100})
	tokens := []string{
		registerForBlobTest(t, handler, "first@example.com"),
		registerForBlobTest(t, handler, "second@example.com"),
	}
	payload := blobPutPayload(t)

	// Twice the cap, across two accounts: the bound is server-wide.
	const total = 2 * maxConcurrentBlobTransfers
	transfers := make([]*pendingTransfer, 0, total)
	for i := range total {
		transfers = append(transfers, startBlobTransfer(context.Background(), handler, http.MethodPut, tokens[i%2], newGatedBody(t, payload)))
	}

	reading := func() []*pendingTransfer {
		var started []*pendingTransfer
		for _, transfer := range transfers {
			select {
			case <-transfer.body.started:
				started = append(started, transfer)
			default:
			}
		}
		return started
	}

	deadline := time.Now().Add(blobSlotWait)
	for len(reading()) < maxConcurrentBlobTransfers && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(blobSlotSilence)
	held := reading()
	if len(held) != maxConcurrentBlobTransfers {
		t.Fatalf("expected exactly %d PUTs reading their body, got %d", maxConcurrentBlobTransfers, len(held))
	}

	// A GET needs a slot too.
	get := startBlobTransfer(context.Background(), handler, http.MethodGet, tokens[0], nil)
	select {
	case <-get.done:
		t.Fatalf("GET finished while every slot was held: %d", get.response.Code)
	case <-time.After(blobSlotSilence):
	}

	// Freeing one slot admits exactly one waiter.
	held[0].body.release()
	<-held[0].done
	admitted := func() bool {
		select {
		case <-get.done:
			return true
		default:
			return len(reading()) > maxConcurrentBlobTransfers
		}
	}
	deadline = time.Now().Add(blobSlotWait)
	for !admitted() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !admitted() {
		t.Fatal("a freed slot admitted no waiter")
	}
	time.Sleep(blobSlotSilence)
	if got := len(reading()); got > maxConcurrentBlobTransfers+1 {
		t.Fatalf("one freed slot admitted %d transfers", got-maxConcurrentBlobTransfers)
	}

	for _, transfer := range transfers {
		transfer.body.release()
	}
	for _, transfer := range append(transfers, get) {
		select {
		case <-transfer.done:
		case <-time.After(blobSlotWait):
			t.Fatal("a blob transfer never finished after every body was released")
		}
		switch transfer.response.Code {
		case http.StatusOK, http.StatusConflict, http.StatusNotFound:
		default:
			t.Fatalf("unexpected status %d: %s", transfer.response.Code, transfer.response.Body.String())
		}
	}
}

func TestBlobTransferWaitingForASlotEndsWithItsClient(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{syncRateLimitCount: 100})
	token := registerForBlobTest(t, handler, "owner@example.com")
	payload := blobPutPayload(t)

	held := make([]*pendingTransfer, 0, maxConcurrentBlobTransfers)
	for range maxConcurrentBlobTransfers {
		transfer := startBlobTransfer(context.Background(), handler, http.MethodPut, token, newGatedBody(t, payload))
		select {
		case <-transfer.body.started:
		case <-time.After(blobSlotWait):
			t.Fatal("a PUT under the cap never reached its body")
		}
		held = append(held, transfer)
	}

	ctx, cancel := context.WithCancel(context.Background())
	waiter := startBlobTransfer(ctx, handler, http.MethodPut, token, newGatedBody(t, payload))
	time.Sleep(blobSlotSilence)
	cancel()
	select {
	case <-waiter.done:
	case <-time.After(blobSlotWait):
		t.Fatal("a waiting PUT outlived its client")
	}
	select {
	case <-waiter.body.started:
		t.Fatal("a PUT read its body without a slot")
	default:
	}

	// The abandoned wait took no slot: after one holder finishes, a new PUT
	// still gets in.
	held[0].body.release()
	<-held[0].done
	next := startBlobTransfer(context.Background(), handler, http.MethodPut, token, newGatedBody(t, payload))
	select {
	case <-next.body.started:
	case <-time.After(blobSlotWait):
		t.Fatal("a slot was lost to the abandoned wait")
	}
	next.body.release()
	<-next.done
	for _, transfer := range held[1:] {
		transfer.body.release()
		<-transfer.done
	}
}
