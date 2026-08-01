package db

import (
	"context"
	"time"
)

// Retention rule kinds.
const (
	// RetentionKeepLast keeps the N most recently updated tags matching the
	// pattern and removes the rest.
	RetentionKeepLast = "keep_last"
	// RetentionMaxAge removes matching tags not updated within a duration.
	RetentionMaxAge = "delete_older_than"
	// RetentionProtect marks matching tags as never removable. It is a rule in
	// its own right so protection can be expressed and audited alongside the
	// rules it overrides.
	RetentionProtect = "protect"
)

// RetentionRule is one policy applied to a repository's tags.
type RetentionRule struct {
	ID        int64     `json:"id"`
	RepoID    int64     `json:"repo_id"`
	Kind      string    `json:"kind"`
	Pattern   string    `json:"pattern"`
	KeepCount int       `json:"keep_count,omitempty"`
	MaxAge    string    `json:"max_age,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// MaxAgeDuration parses the rule's retention window. A malformed or absent
// value yields zero, which callers treat as "no age limit" rather than
// "everything is expired".
func (r *RetentionRule) MaxAgeDuration() time.Duration {
	if r.MaxAge == "" {
		return 0
	}
	d, err := time.ParseDuration(r.MaxAge)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

const retentionCols = `id, repo_id, kind, pattern, keep_count, max_age, enabled, created_at`

func scanRetentionRule(row interface{ Scan(...any) error }) (*RetentionRule, error) {
	var r RetentionRule
	var enabled int
	var created string
	if err := row.Scan(&r.ID, &r.RepoID, &r.Kind, &r.Pattern, &r.KeepCount,
		&r.MaxAge, &enabled, &created); err != nil {
		return nil, err
	}
	r.Enabled = enabled != 0
	r.CreatedAt = parseTS(created)
	return &r, nil
}

func (d *DB) CreateRetentionRule(ctx context.Context, r *RetentionRule) (*RetentionRule, error) {
	now := nowStr()
	res, err := d.ExecContext(ctx, `INSERT INTO retention_rules
		(repo_id, kind, pattern, keep_count, max_age, enabled, created_at)
		VALUES (?,?,?,?,?,?,?)`,
		r.RepoID, r.Kind, r.Pattern, r.KeepCount, r.MaxAge, boolInt(r.Enabled), now)
	if err != nil {
		return nil, err
	}
	r.ID, _ = res.LastInsertId()
	r.CreatedAt = parseTS(now)
	return r, nil
}

func (d *DB) RetentionRules(ctx context.Context, repoID int64) ([]*RetentionRule, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+retentionCols+` FROM retention_rules WHERE repo_id = ? ORDER BY id`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*RetentionRule{}
	for rows.Next() {
		r, err := scanRetentionRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AllRetentionRules groups every enabled rule by repository, for a sweep across
// the whole registry.
func (d *DB) AllRetentionRules(ctx context.Context) (map[int64][]*RetentionRule, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+retentionCols+` FROM retention_rules WHERE enabled = 1 ORDER BY repo_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]*RetentionRule{}
	for rows.Next() {
		r, err := scanRetentionRule(rows)
		if err != nil {
			return nil, err
		}
		out[r.RepoID] = append(out[r.RepoID], r)
	}
	return out, rows.Err()
}

func (d *DB) DeleteRetentionRule(ctx context.Context, repoID, id int64) error {
	_, err := d.ExecContext(ctx,
		`DELETE FROM retention_rules WHERE id = ? AND repo_id = ?`, id, repoID)
	return err
}

func (d *DB) SetRetentionRuleEnabled(ctx context.Context, repoID, id int64, enabled bool) error {
	_, err := d.ExecContext(ctx,
		`UPDATE retention_rules SET enabled = ? WHERE id = ? AND repo_id = ?`,
		boolInt(enabled), id, repoID)
	return err
}

// ---------------------------------------------------------------- run history

// MaintenanceRun records one execution of retention or garbage collection.
type MaintenanceRun struct {
	ID           int64     `json:"id"`
	Kind         string    `json:"kind"`
	Trigger      string    `json:"trigger"`
	DryRun       bool      `json:"dry_run"`
	TagsDeleted  int       `json:"tags_deleted"`
	BlobsDeleted int       `json:"blobs_deleted"`
	BytesFreed   int64     `json:"bytes_freed"`
	Detail       string    `json:"detail,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	DurationMS   int64     `json:"duration_ms"`
}

func (d *DB) RecordMaintenanceRun(ctx context.Context, r *MaintenanceRun) error {
	_, err := d.ExecContext(ctx, `INSERT INTO maintenance_runs
		(kind, trigger, dry_run, tags_deleted, blobs_deleted, bytes_freed,
		 detail, started_at, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		r.Kind, r.Trigger, boolInt(r.DryRun), r.TagsDeleted, r.BlobsDeleted,
		r.BytesFreed, r.Detail, r.StartedAt.UTC().Format(tsLayout), r.DurationMS)
	return err
}

func (d *DB) MaintenanceRuns(ctx context.Context, limit int) ([]*MaintenanceRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `
		SELECT id, kind, trigger, dry_run, tags_deleted, blobs_deleted,
		       bytes_freed, detail, started_at, duration_ms
		FROM maintenance_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*MaintenanceRun{}
	for rows.Next() {
		var r MaintenanceRun
		var dry int
		var started string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Trigger, &dry, &r.TagsDeleted,
			&r.BlobsDeleted, &r.BytesFreed, &r.Detail, &started, &r.DurationMS); err != nil {
			return nil, err
		}
		r.DryRun = dry != 0
		r.StartedAt = parseTS(started)
		out = append(out, &r)
	}
	return out, rows.Err()
}
