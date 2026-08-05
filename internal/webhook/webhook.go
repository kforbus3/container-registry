// Package webhook delivers registry events to HTTP endpoints.
//
// Deliveries are signed, retried, and recorded. They never block the request
// that produced the event: a receiver that is slow or down must not become
// backpressure on a push.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
)

// Event is what gets delivered.
type Event struct {
	Event      string         `json:"event"`
	Repository string         `json:"repository,omitempty"`
	Reference  string         `json:"reference,omitempty"`
	Digest     string         `json:"digest,omitempty"`
	Actor      string         `json:"actor,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	Data       map[string]any `json:"data,omitempty"`

	// RepoID routes the event to the right subscribers and is not serialised.
	RepoID int64 `json:"-"`
}

// Signature headers. The timestamp is signed alongside the body so a captured
// delivery cannot be replayed indefinitely.
const (
	HeaderEvent     = "X-Registry-Event"
	HeaderDelivery  = "X-Registry-Delivery"
	HeaderSignature = "X-Registry-Signature-256"
	HeaderTimestamp = "X-Registry-Timestamp"
)

// Sign computes the delivery signature: HMAC-SHA256 over "timestamp.body".
func Sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Dispatcher queues events and delivers them on background workers.
type Dispatcher struct {
	DB  *db.DB
	Log *slog.Logger

	// Attempts is how many times a delivery is tried before being given up on.
	Attempts int
	// Timeout bounds a single delivery attempt.
	Timeout time.Duration
	// AllowInternal permits delivery to loopback, link-local and private
	// addresses.
	AllowInternal bool

	http  *http.Client
	queue chan Event
	wg    sync.WaitGroup

	mu    sync.Mutex
	stats Stats
}

// Stats reports dispatcher activity.
type Stats struct {
	Queued    int64 `json:"queued"`
	Delivered int64 `json:"delivered"`
	Failed    int64 `json:"failed"`
	Dropped   int64 `json:"dropped"`
}

func New(database *db.DB, log *slog.Logger, queueDepth int, timeout time.Duration) *Dispatcher {
	return NewWithOptions(database, log, queueDepth, timeout, false)
}

// NewWithOptions builds a dispatcher that may be permitted to deliver to
// internal addresses. See destination.go for what that means and why it is off
// by default.
func NewWithOptions(database *db.DB, log *slog.Logger, queueDepth int, timeout time.Duration, allowInternal bool) *Dispatcher {
	if queueDepth <= 0 {
		queueDepth = 512
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Control: dialGuard(allowInternal)}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	return &Dispatcher{
		DB: database, Log: log, Attempts: 3, Timeout: timeout,
		AllowInternal: allowInternal,
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// A redirect is a second destination, chosen by the receiver rather
			// than by the administrator who wrote the URL. Following one would
			// undo the check that was just made, so deliveries do not follow
			// them: a webhook receiver has no reason to redirect.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		queue: make(chan Event, queueDepth),
	}
}

func (d *Dispatcher) Start(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ev, ok := <-d.queue:
					if !ok {
						return
					}
					d.deliver(ctx, ev)
				}
			}
		}()
	}
}

func (d *Dispatcher) Wait() { d.wg.Wait() }

func (d *Dispatcher) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// Emit queues an event. It never blocks: a full queue drops the event and
// counts it, because a push must not wait on a webhook receiver.
func (d *Dispatcher) Emit(ev Event) {
	if d == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	d.mu.Lock()
	d.stats.Queued++
	d.mu.Unlock()

	select {
	case d.queue <- ev:
	default:
		d.mu.Lock()
		d.stats.Dropped++
		d.mu.Unlock()
		d.Log.Warn("webhook queue full, dropping event",
			"event", ev.Event, "repository", ev.Repository)
	}
}

func (d *Dispatcher) deliver(ctx context.Context, ev Event) {
	hooks, err := d.DB.WebhooksFor(ctx, ev.RepoID)
	if err != nil {
		d.Log.Error("could not load webhooks", "err", err)
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	for _, h := range hooks {
		if !h.Subscribes(ev.Event) {
			continue
		}
		d.send(ctx, h, ev, body)
	}
}

func (d *Dispatcher) send(ctx context.Context, h *db.Webhook, ev Event, body []byte) {
	started := time.Now()
	var (
		status  int
		lastErr string
		attempt int
	)

	for attempt = 1; attempt <= d.Attempts; attempt++ {
		status, lastErr = d.attempt(ctx, h, ev, body)
		// 2xx is success. A 4xx other than 429 will not improve on retry, so
		// there is no point hammering a receiver that has rejected the shape
		// of the request.
		if status >= 200 && status < 300 {
			lastErr = ""
			break
		}
		if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
			break
		}
		if attempt < d.Attempts {
			// Exponential backoff, so a receiver coming back up is not met with
			// a thundering herd.
			delay := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}

	d.mu.Lock()
	if lastErr == "" && status >= 200 && status < 300 {
		d.stats.Delivered++
	} else {
		d.stats.Failed++
	}
	d.mu.Unlock()

	d.DB.RecordDelivery(context.WithoutCancel(ctx), &db.WebhookDelivery{
		WebhookID: h.ID, Event: ev.Event,
		Repository: ev.Repository, Reference: ev.Reference,
		StatusCode: status, Error: lastErr, Attempts: attempt,
		DurationMS: time.Since(started).Milliseconds(),
	})
	if lastErr != "" {
		d.Log.Warn("webhook delivery failed",
			"webhook", h.Name, "event", ev.Event, "status", status, "err", lastErr)
	}
}

func (d *Dispatcher) attempt(ctx context.Context, h *db.Webhook, ev Event, body []byte) (int, string) {
	reqCtx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	ts := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "container-registry/webhook")
	req.Header.Set(HeaderEvent, ev.Event)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderDelivery, fmt.Sprintf("%d-%d", h.ID, ts))
	if h.Secret != "" {
		req.Header.Set(HeaderSignature, Sign(h.Secret, ts, body))
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, "receiver returned " + resp.Status
	}
	return resp.StatusCode, ""
}
