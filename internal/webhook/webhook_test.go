package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
)

func newTestDispatcher(t *testing.T) (*Dispatcher, *db.DB) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	// Test receivers are httptest servers on loopback, which delivery refuses by
	// default — that refusal is what TestRefusesInternalDestinations covers.
	d := NewWithOptions(database, slog.New(slog.NewTextHandler(io.Discard, nil)), 16, 2*time.Second, true)
	return d, database
}

// receiver is a test endpoint that records what it was sent.
type receiver struct {
	mu       sync.Mutex
	calls    int32
	bodies   [][]byte
	headers  []http.Header
	status   int32
	failures int32
}

func (rc *receiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.bodies = append(rc.bodies, body)
		rc.headers = append(rc.headers, r.Header.Clone())
		rc.mu.Unlock()
		atomic.AddInt32(&rc.calls, 1)

		// Fail the first N attempts, to exercise retry.
		if atomic.LoadInt32(&rc.failures) > 0 {
			atomic.AddInt32(&rc.failures, -1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		code := int(atomic.LoadInt32(&rc.status))
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
	}
}

func TestSignatureIsStableAndSecretDependent(t *testing.T) {
	body := []byte(`{"event":"push.tag"}`)
	a := Sign("shhh", 1750000000, body)
	if a != Sign("shhh", 1750000000, body) {
		t.Fatal("signing is not deterministic")
	}
	// The timestamp is part of the signature, so a captured delivery cannot be
	// replayed indefinitely.
	if a == Sign("shhh", 1750000001, body) {
		t.Fatal("the timestamp is not covered by the signature")
	}
	if a == Sign("different", 1750000000, body) {
		t.Fatal("the signature does not depend on the secret")
	}
	if a == Sign("shhh", 1750000000, []byte(`{"event":"delete.tag"}`)) {
		t.Fatal("the signature does not depend on the body")
	}
	if len(a) < 8 || a[:7] != "sha256=" {
		t.Fatalf("signature %q is not in the expected form", a)
	}
}

func TestDeliversSignedEvent(t *testing.T) {
	d, database := newTestDispatcher(t)
	rc := &receiver{}
	srv := httptest.NewServer(rc.handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx, 1)

	if _, err := database.CreateWebhook(ctx, &db.Webhook{
		Name: "test", URL: srv.URL, Secret: "shhh", Events: "*", Enabled: true,
	}); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	d.Emit(Event{Event: db.EventPushTag, Repository: "team/app", Reference: "v1"})
	waitFor(t, func() bool { return atomic.LoadInt32(&rc.calls) >= 1 })

	rc.mu.Lock()
	body, hdr := rc.bodies[0], rc.headers[0]
	rc.mu.Unlock()

	var got Event
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if got.Event != db.EventPushTag || got.Repository != "team/app" || got.Reference != "v1" {
		t.Fatalf("payload = %+v", got)
	}
	if hdr.Get(HeaderEvent) != db.EventPushTag {
		t.Errorf("%s = %q", HeaderEvent, hdr.Get(HeaderEvent))
	}
	// The receiver must be able to verify the delivery came from us.
	ts, err := strconv.ParseInt(hdr.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		t.Fatalf("timestamp header: %v", err)
	}
	if want := Sign("shhh", ts, body); hdr.Get(HeaderSignature) != want {
		t.Fatalf("signature = %q, want %q", hdr.Get(HeaderSignature), want)
	}
}

// A receiver that is briefly down must not lose the event.
func TestRetriesOnServerError(t *testing.T) {
	d, database := newTestDispatcher(t)
	d.Attempts = 3
	rc := &receiver{}
	atomic.StoreInt32(&rc.failures, 1) // fail once, then succeed
	srv := httptest.NewServer(rc.handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx, 1)
	database.CreateWebhook(ctx, &db.Webhook{
		Name: "flaky", URL: srv.URL, Events: "*", Enabled: true,
	})

	d.Emit(Event{Event: db.EventPushTag, Repository: "team/app"})
	waitFor(t, func() bool { return atomic.LoadInt32(&rc.calls) >= 2 })

	if d.Stats().Delivered != 1 {
		t.Fatalf("stats = %+v, want one successful delivery", d.Stats())
	}
}

// A 4xx will not improve on retry, so hammering the receiver is pointless.
func TestDoesNotRetryClientErrors(t *testing.T) {
	d, database := newTestDispatcher(t)
	d.Attempts = 3
	rc := &receiver{}
	atomic.StoreInt32(&rc.status, http.StatusBadRequest)
	srv := httptest.NewServer(rc.handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx, 1)
	database.CreateWebhook(ctx, &db.Webhook{
		Name: "rejecting", URL: srv.URL, Events: "*", Enabled: true,
	})

	d.Emit(Event{Event: db.EventPushTag})
	waitFor(t, func() bool { return d.Stats().Failed >= 1 })
	time.Sleep(200 * time.Millisecond) // give any stray retry a chance to land

	if n := atomic.LoadInt32(&rc.calls); n != 1 {
		t.Fatalf("receiver was called %d times, want exactly 1 for a 4xx", n)
	}
}

func TestEventFiltering(t *testing.T) {
	d, database := newTestDispatcher(t)
	rc := &receiver{}
	srv := httptest.NewServer(rc.handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx, 1)
	database.CreateWebhook(ctx, &db.Webhook{
		Name: "deletes-only", URL: srv.URL,
		Events: db.EventDeleteTag, Enabled: true,
	})

	// Not subscribed: must not be delivered.
	d.Emit(Event{Event: db.EventPushTag})
	time.Sleep(300 * time.Millisecond)
	if n := atomic.LoadInt32(&rc.calls); n != 0 {
		t.Fatalf("an unsubscribed event was delivered (%d calls)", n)
	}
	// Subscribed: must be.
	d.Emit(Event{Event: db.EventDeleteTag})
	waitFor(t, func() bool { return atomic.LoadInt32(&rc.calls) == 1 })
}

func TestSubscribes(t *testing.T) {
	cases := []struct {
		events, event string
		want          bool
	}{
		{"*", db.EventPushTag, true},
		{"", db.EventPushTag, true},
		{db.EventPushTag, db.EventPushTag, true},
		{db.EventPushTag, db.EventDeleteTag, false},
		{"push.tag, delete.tag", db.EventDeleteTag, true},
		{"push.tag, delete.tag", db.EventScanComplete, false},
	}
	for _, c := range cases {
		w := &db.Webhook{Events: c.events}
		if got := w.Subscribes(c.event); got != c.want {
			t.Errorf("events %q vs %q = %v, want %v", c.events, c.event, got, c.want)
		}
	}
}

// A disabled webhook receives nothing.
func TestDisabledWebhookIsSilent(t *testing.T) {
	d, database := newTestDispatcher(t)
	rc := &receiver{}
	srv := httptest.NewServer(rc.handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx, 1)
	database.CreateWebhook(ctx, &db.Webhook{
		Name: "off", URL: srv.URL, Events: "*", Enabled: false,
	})

	d.Emit(Event{Event: db.EventPushTag})
	time.Sleep(300 * time.Millisecond)
	if n := atomic.LoadInt32(&rc.calls); n != 0 {
		t.Fatalf("a disabled webhook was delivered to (%d calls)", n)
	}
}

// Emitting must never block the caller, because the caller is serving a push.
func TestEmitNeverBlocks(t *testing.T) {
	d, _ := newTestDispatcher(t) // workers never started, so nothing drains
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			d.Emit(Event{Event: db.EventPushTag})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit blocked when the queue was full")
	}
	if d.Stats().Dropped == 0 {
		t.Fatal("a saturated queue must drop and count events")
	}
}

// Emit on a nil dispatcher is a no-op, so call sites need no guard.
func TestNilDispatcherIsSafe(t *testing.T) {
	var d *Dispatcher
	d.Emit(Event{Event: db.EventPushTag})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the expected condition")
}
