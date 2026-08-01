package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Webhook events. A webhook subscribes to a comma-separated list of these, or
// "*" for everything.
const (
	EventPushTag        = "push.tag"
	EventPushManifest   = "push.manifest"
	EventDeleteTag      = "delete.tag"
	EventDeleteManifest = "delete.manifest"
	EventRetentionTag   = "retention.delete_tag"
)

// AllEvents lists every event a webhook can subscribe to.
var AllEvents = []string{
	EventPushTag, EventPushManifest, EventDeleteTag,
	EventDeleteManifest, EventRetentionTag,
}

// Webhook is a registered delivery target.
type Webhook struct {
	ID     int64  `json:"id"`
	RepoID *int64 `json:"repo_id,omitempty"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	// Secret is never returned by the API; it only signs outgoing deliveries.
	Secret     string    `json:"-"`
	HasSecret  bool      `json:"has_secret"`
	Events     string    `json:"events"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	LastStatus int       `json:"last_status,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	LastSentAt string    `json:"last_sent_at,omitempty"`
}

// Subscribes reports whether the webhook wants an event.
func (w *Webhook) Subscribes(event string) bool {
	spec := strings.TrimSpace(w.Events)
	if spec == "" || spec == "*" {
		return true
	}
	for _, e := range strings.Split(spec, ",") {
		if strings.TrimSpace(e) == event {
			return true
		}
	}
	return false
}

const webhookCols = `id, repo_id, name, url, secret, events, enabled, created_at,
	last_status, last_error, last_sent_at`

func scanWebhook(row interface{ Scan(...any) error }) (*Webhook, error) {
	var w Webhook
	var repoID sql.NullInt64
	var enabled int
	var created string
	if err := row.Scan(&w.ID, &repoID, &w.Name, &w.URL, &w.Secret, &w.Events,
		&enabled, &created, &w.LastStatus, &w.LastError, &w.LastSentAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if repoID.Valid {
		id := repoID.Int64
		w.RepoID = &id
	}
	w.Enabled = enabled != 0
	w.HasSecret = w.Secret != ""
	w.CreatedAt = parseTS(created)
	return &w, nil
}

func (d *DB) CreateWebhook(ctx context.Context, w *Webhook) (*Webhook, error) {
	now := nowStr()
	var repoID any
	if w.RepoID != nil {
		repoID = *w.RepoID
	}
	res, err := d.ExecContext(ctx, `INSERT INTO webhooks
		(repo_id, name, url, secret, events, enabled, created_at)
		VALUES (?,?,?,?,?,?,?)`,
		repoID, w.Name, w.URL, w.Secret, w.Events, boolInt(w.Enabled), now)
	if err != nil {
		return nil, err
	}
	w.ID, _ = res.LastInsertId()
	w.CreatedAt = parseTS(now)
	w.HasSecret = w.Secret != ""
	return w, nil
}

// WebhooksFor returns the hooks that should receive an event for a repository:
// those scoped to it, plus every registry-wide hook.
func (d *DB) WebhooksFor(ctx context.Context, repoID int64) ([]*Webhook, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+webhookCols+` FROM webhooks
		 WHERE enabled = 1 AND (repo_id IS NULL OR repo_id = ?) ORDER BY id`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Webhook{}
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListWebhooks returns hooks for one repository, or the registry-wide ones when
// repoID is zero.
func (d *DB) ListWebhooks(ctx context.Context, repoID int64) ([]*Webhook, error) {
	q := `SELECT ` + webhookCols + ` FROM webhooks WHERE repo_id IS NULL ORDER BY id`
	var args []any
	if repoID != 0 {
		q = `SELECT ` + webhookCols + ` FROM webhooks WHERE repo_id = ? ORDER BY id`
		args = append(args, repoID)
	}
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Webhook{}
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (d *DB) GetWebhook(ctx context.Context, id int64) (*Webhook, error) {
	return scanWebhook(d.QueryRowContext(ctx,
		`SELECT `+webhookCols+` FROM webhooks WHERE id = ?`, id))
}

func (d *DB) DeleteWebhook(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id)
	return err
}

func (d *DB) SetWebhookEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := d.ExecContext(ctx,
		`UPDATE webhooks SET enabled = ? WHERE id = ?`, boolInt(enabled), id)
	return err
}

// WebhookDelivery records one attempt to deliver an event.
type WebhookDelivery struct {
	ID         int64     `json:"id"`
	WebhookID  int64     `json:"webhook_id"`
	Event      string    `json:"event"`
	Repository string    `json:"repository,omitempty"`
	Reference  string    `json:"reference,omitempty"`
	StatusCode int       `json:"status_code"`
	Error      string    `json:"error,omitempty"`
	Attempts   int       `json:"attempts"`
	DurationMS int64     `json:"duration_ms"`
	SentAt     time.Time `json:"sent_at"`
}

func (d *DB) RecordDelivery(ctx context.Context, del *WebhookDelivery) error {
	now := nowStr()
	if _, err := d.ExecContext(ctx, `INSERT INTO webhook_deliveries
		(webhook_id, event, repository, reference, status_code, error, attempts, duration_ms, sent_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		del.WebhookID, del.Event, del.Repository, del.Reference,
		del.StatusCode, del.Error, del.Attempts, del.DurationMS, now); err != nil {
		return err
	}
	// Mirror the outcome onto the webhook so its health is visible without a
	// join against the delivery history.
	_, err := d.ExecContext(ctx,
		`UPDATE webhooks SET last_status = ?, last_error = ?, last_sent_at = ? WHERE id = ?`,
		del.StatusCode, del.Error, now, del.WebhookID)
	return err
}

func (d *DB) Deliveries(ctx context.Context, webhookID int64, limit int) ([]*WebhookDelivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 25
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, webhook_id, event, repository, reference, status_code,
		       error, attempts, duration_ms, sent_at
		FROM webhook_deliveries WHERE webhook_id = ? ORDER BY id DESC LIMIT ?`,
		webhookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*WebhookDelivery{}
	for rows.Next() {
		var del WebhookDelivery
		var sent string
		if err := rows.Scan(&del.ID, &del.WebhookID, &del.Event, &del.Repository,
			&del.Reference, &del.StatusCode, &del.Error, &del.Attempts,
			&del.DurationMS, &sent); err != nil {
			return nil, err
		}
		del.SentAt = parseTS(sent)
		out = append(out, &del)
	}
	return out, rows.Err()
}

// PruneDeliveries keeps the delivery log bounded.
func (d *DB) PruneDeliveries(ctx context.Context, keepPerHook int) error {
	if keepPerHook <= 0 {
		keepPerHook = 100
	}
	_, err := d.ExecContext(ctx, `
		DELETE FROM webhook_deliveries WHERE id NOT IN (
			SELECT id FROM (
				SELECT id, ROW_NUMBER() OVER (PARTITION BY webhook_id ORDER BY id DESC) AS rn
				FROM webhook_deliveries
			) WHERE rn <= ?
		)`, keepPerHook)
	return err
}
