package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	return startSlotTransfer(ctx, handler, method, "/sync/blob", token, body)
}

func startSlotTransfer(ctx context.Context, handler http.Handler, method, path, token string, body *gatedBody) *pendingTransfer {
	transfer := &pendingTransfer{body: body, response: httptest.NewRecorder(), done: make(chan struct{})}
	var request *http.Request
	if body != nil {
		request = httptest.NewRequestWithContext(ctx, method, path, body)
		request.Header.Set("Content-Type", "application/json")
	} else {
		request = httptest.NewRequestWithContext(ctx, method, path, nil)
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

// holdEveryBlobSlot fills every slot with a gated PUT, one account per slot as
// the per-account cap requires.
func holdEveryBlobSlot(t *testing.T, handler http.Handler, payload []byte) []*pendingTransfer {
	t.Helper()
	held := make([]*pendingTransfer, 0, maxConcurrentBlobTransfers)
	for i := range maxConcurrentBlobTransfers {
		token := registerForBlobTest(t, handler, fmt.Sprintf("holder%d@example.com", i))
		transfer := startBlobTransfer(context.Background(), handler, http.MethodPut, token, newGatedBody(t, payload))
		select {
		case <-transfer.body.started:
		case <-time.After(blobSlotWait):
			t.Fatal("a PUT under the cap never reached its body")
		}
		held = append(held, transfer)
	}
	return held
}

func expectBlobTransferBusy(t *testing.T, response *httptest.ResponseRecorder, retryAfter string) {
	t.Helper()
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", response.Code, response.Body.String())
	}
	expectErrorKey(t, response.Body.Bytes(), "blob_transfer_busy")
	if got := response.Header().Get("Retry-After"); got != retryAfter {
		t.Fatalf("Retry-After = %q, want %s", got, retryAfter)
	}
}

func TestConcurrentBlobTransfersNeverExceedTheCap(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 100, syncRateLimitCount: 100, blobSlotWait: time.Minute})
	payload := blobPutPayload(t)

	// More transfers than slots, one account each: distinct accounts share
	// the server-wide bound.
	const total = maxConcurrentBlobTransfers + 2
	transfers := make([]*pendingTransfer, 0, total)
	for i := range total {
		token := registerForBlobTest(t, handler, fmt.Sprintf("account%d@example.com", i))
		transfers = append(transfers, startBlobTransfer(context.Background(), handler, http.MethodPut, token, newGatedBody(t, payload)))
	}
	readerToken := registerForBlobTest(t, handler, "reader@example.com")

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
	get := startBlobTransfer(context.Background(), handler, http.MethodGet, readerToken, nil)
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
	handler := newTestServerWithOptions(t, serverTestOptions{syncRateLimitCount: 100, blobSlotWait: time.Minute})
	payload := blobPutPayload(t)
	held := holdEveryBlobSlot(t, handler, payload)
	token := registerForBlobTest(t, handler, "owner@example.com")
	readerToken := registerForBlobTest(t, handler, "reader@example.com")

	ctx, cancel := context.WithCancel(context.Background())
	waiter := startBlobTransfer(ctx, handler, http.MethodPut, token, newGatedBody(t, payload))
	getWaiter := startBlobTransfer(ctx, handler, http.MethodGet, readerToken, nil)
	time.Sleep(blobSlotSilence)
	select {
	case <-getWaiter.done:
		t.Fatalf("GET finished while every slot was held: %d", getWaiter.response.Code)
	default:
	}
	cancel()
	for _, pending := range []*pendingTransfer{waiter, getWaiter} {
		select {
		case <-pending.done:
		case <-time.After(blobSlotWait):
			t.Fatal("a waiting blob transfer outlived its client")
		}
	}
	select {
	case <-waiter.body.started:
		t.Fatal("a PUT read its body without a slot")
	default:
	}

	// The abandoned waits took no slot and left no account mark: after one
	// holder finishes, the waiters' accounts get in again.
	held[0].body.release()
	<-held[0].done
	next := startBlobTransfer(context.Background(), handler, http.MethodPut, token, newGatedBody(t, payload))
	select {
	case <-next.body.started:
	case <-time.After(blobSlotWait):
		t.Fatal("a slot or the account mark was lost to the abandoned wait")
	}
	next.body.release()
	<-next.done
	for _, transfer := range held[1:] {
		transfer.body.release()
		<-transfer.done
	}
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, readerToken, http.StatusNotFound)
}

func TestBlobTransferWaitingPastTheBoundGetsBusyNotInvalidJSON(t *testing.T) {
	const bound = 300 * time.Millisecond
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 100, syncRateLimitCount: 10, syncRateLimitWindow: time.Minute, blobSlotWait: bound})
	payload := blobPutPayload(t)
	held := holdEveryBlobSlot(t, handler, payload)
	token := registerForBlobTest(t, handler, "owner@example.com")
	getToken := registerForBlobTest(t, handler, "reader@example.com")
	rekeyToken := registerForBlobTest(t, handler, "rekeyer@example.com")

	started := time.Now()
	putWaiter := startBlobTransfer(context.Background(), handler, http.MethodPut, token, newGatedBody(t, payload))
	getWaiter := startBlobTransfer(context.Background(), handler, http.MethodGet, getToken, nil)
	rekeyWaiter := startSlotTransfer(context.Background(), handler, http.MethodPut, "/sync/rekey", rekeyToken, newGatedBody(t, payload))
	for _, waiter := range []*pendingTransfer{putWaiter, getWaiter, rekeyWaiter} {
		select {
		case <-waiter.done:
		case <-time.After(blobSlotWait):
			t.Fatal("a blob transfer waited past the bound without an answer")
		}
		if elapsed := time.Since(started); elapsed < bound {
			t.Fatalf("answered after %v, before the %v bound", elapsed, bound)
		}
		// 10 per minute paces retries at one per 6 s.
		expectBlobTransferBusy(t, waiter.response, "6")
	}
	for _, refused := range []*pendingTransfer{putWaiter, rekeyWaiter} {
		select {
		case <-refused.body.started:
			t.Fatal("a refused PUT read its body")
		default:
		}
	}

	// The refused waits took no slot and left no account mark: a freed slot
	// still admits a new PUT from a refused account.
	held[0].body.release()
	<-held[0].done
	next := startBlobTransfer(context.Background(), handler, http.MethodPut, token, newGatedBody(t, payload))
	select {
	case <-next.body.started:
	case <-time.After(blobSlotWait):
		t.Fatal("a slot or the account mark was lost to a refused wait")
	}
	next.body.release()
	<-next.done
	for _, transfer := range held[1:] {
		transfer.body.release()
		<-transfer.done
	}
	for _, refusedToken := range []string{getToken, rekeyToken} {
		performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, refusedToken, http.StatusNotFound)
	}
}

// One account holds at most one slot: while its first transfer, a blob PUT or
// a re-key, holds a slot, every further blob transfer of that account answers
// 503 at once, reads no body, takes no slot and leaves the first's mark in
// place; other accounts keep every remaining slot.
func TestSecondBlobTransferFromOneAccountIsRefusedAtOnce(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{syncRateLimitCount: 20, syncRateLimitWindow: time.Minute, blobSlotWait: time.Minute})
	token := registerForBlobTest(t, handler, "owner@example.com")
	payload := blobPutPayload(t)

	for _, firstPath := range []string{"/sync/blob", "/sync/rekey"} {
		first := startSlotTransfer(context.Background(), handler, http.MethodPut, firstPath, token, newGatedBody(t, payload))
		select {
		case <-first.body.started:
		case <-time.After(blobSlotWait):
			t.Fatalf("PUT %s never reached its body", firstPath)
		}

		seconds := []struct {
			method, path string
			body         *gatedBody
		}{
			{http.MethodPut, "/sync/blob", newGatedBody(t, payload)},
			{http.MethodGet, "/sync/blob", nil},
			{http.MethodPut, "/sync/rekey", newGatedBody(t, payload)},
		}
		for _, second := range seconds {
			started := time.Now()
			refused := startSlotTransfer(context.Background(), handler, second.method, second.path, token, second.body)
			select {
			case <-refused.done:
			case <-time.After(blobSlotWait):
				t.Fatalf("%s %s behind PUT %s waited for a slot instead of being refused", second.method, second.path, firstPath)
			}
			if elapsed := time.Since(started); elapsed >= blobSlotWait {
				t.Fatalf("%s %s refused after %v", second.method, second.path, elapsed)
			}
			// 20 per minute paces retries at one per 3 s.
			expectBlobTransferBusy(t, refused.response, "3")
			if second.body != nil {
				select {
				case <-second.body.started:
					t.Fatalf("a refused %s %s read its body", second.method, second.path)
				default:
				}
			}
		}

		first.body.release()
		<-first.done
		// The re-key's blob-shaped body fails validation; only a 503 would
		// mean the holder lost its slot.
		if firstPath == "/sync/blob" && first.response.Code != http.StatusOK ||
			first.response.Code == http.StatusServiceUnavailable {
			t.Fatalf("PUT %s holding the slot answered %d: %s", firstPath, first.response.Code, first.response.Body.String())
		}
	}

	// The finished transfers released the mark, and the six refusals took no
	// slot: the owner gets in again and every slot is still free.
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, token, http.StatusOK)
	for _, transfer := range holdEveryBlobSlot(t, handler, payload) {
		transfer.body.release()
		<-transfer.done
	}
}

func TestBlobSlotWaitForStaysWellUnderTheHTTPTimeouts(t *testing.T) {
	cases := []struct {
		read, write, want time.Duration
	}{
		{10 * time.Second, 15 * time.Second, defaultBlobSlotWait},
		{time.Minute, time.Minute, defaultBlobSlotWait},
		{4 * time.Second, 15 * time.Second, time.Second},
		{10 * time.Second, 2 * time.Second, 500 * time.Millisecond},
		{0, 0, defaultBlobSlotWait},
		{2 * time.Nanosecond, time.Minute, time.Nanosecond},
	}
	for _, c := range cases {
		if got := BlobSlotWaitFor(c.read, c.write); got != c.want {
			t.Errorf("BlobSlotWaitFor(%v, %v) = %v, want %v", c.read, c.write, got, c.want)
		}
	}
}

func TestBlobTransferBusyRetryAfterKeepsRetriesInsideTheSyncBudget(t *testing.T) {
	cases := []struct {
		count  int
		window time.Duration
		want   int64
	}{
		{10, time.Minute, 6},
		{100, time.Minute, 2},
		{5, 15 * time.Minute, 180},
		{7, time.Minute, 9},
		{0, time.Minute, 2},
		{10, 0, 2},
	}
	for _, c := range cases {
		if got := blobTransferBusyRetryAfter(c.count, c.window); got != c.want {
			t.Errorf("blobTransferBusyRetryAfter(%d, %v) = %d, want %d", c.count, c.window, got, c.want)
		}
	}
}

func TestFreeBlobSlotWinsOverAnExpiredWait(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{syncRateLimitCount: 100, blobSlotWait: -time.Second})
	token := registerForBlobTest(t, handler, "owner@example.com")
	for range 50 {
		transfer := startBlobTransfer(context.Background(), handler, http.MethodGet, token, nil)
		<-transfer.done
		if transfer.response.Code != http.StatusNotFound {
			t.Fatalf("expected 404 with every slot free, got %d: %s", transfer.response.Code, transfer.response.Body.String())
		}
	}
}

func TestNewServerDefaultsTheBlobSlotWait(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{})
	if got := handler.(*Server).blobSlotWait; got != defaultBlobSlotWait {
		t.Fatalf("blobSlotWait = %v, want %v", got, defaultBlobSlotWait)
	}
}
