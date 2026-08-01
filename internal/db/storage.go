package db

import (
	"context"
	"fmt"
	"strings"
)

// Named storage backends and the rules that route repositories to them.

// StorageBackend is one configured place blobs can live.
type StorageBackend struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Config string `json:"-"` // holds a sealed credential; never serialised out
}

// StorageRule maps a repository name pattern onto a backend.
type StorageRule struct {
	ID       int64  `json:"id"`
	Pattern  string `json:"pattern"`
	Backend  string `json:"backend"`
	Priority int    `json:"priority"`
}

func (d *DB) ListStorageBackends(ctx context.Context) ([]StorageBackend, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, name, config FROM storage_backends ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StorageBackend
	for rows.Next() {
		var b StorageBackend
		if err := rows.Scan(&b.ID, &b.Name, &b.Config); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (d *DB) GetStorageBackend(ctx context.Context, name string) (*StorageBackend, error) {
	var b StorageBackend
	err := d.QueryRowContext(ctx,
		`SELECT id, name, config FROM storage_backends WHERE name = ?`, name).
		Scan(&b.ID, &b.Name, &b.Config)
	if err != nil {
		return nil, ErrNotFound
	}
	return &b, nil
}

// SaveStorageBackend creates or updates a backend by name.
func (d *DB) SaveStorageBackend(ctx context.Context, name, config string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("a backend needs a name")
	}
	_, err := d.ExecContext(ctx, `INSERT INTO storage_backends
		(name, config, created_at, updated_at) VALUES (?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at`,
		name, config, nowStr(), nowStr())
	return err
}

// DeleteStorageBackend removes a backend.
//
// It refuses while a rule still points at it: deleting one out from under a
// rule would leave repositories resolving to nothing, and the alternative --
// silently falling back to the default -- is how content ends up in the wrong
// bucket.
func (d *DB) DeleteStorageBackend(ctx context.Context, name string) error {
	var used int
	if err := d.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM storage_rules r
		  JOIN storage_backends b ON b.id = r.backend_id
		 WHERE b.name = ?`, name).Scan(&used); err != nil {
		return err
	}
	if used > 0 {
		return fmt.Errorf("%d storage rule(s) still route to %q; remove them first", used, name)
	}
	_, err := d.ExecContext(ctx, `DELETE FROM storage_backends WHERE name = ?`, name)
	return err
}

// ListStorageRules returns the rules in evaluation order.
func (d *DB) ListStorageRules(ctx context.Context) ([]StorageRule, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT r.id, r.pattern, b.name, r.priority
		  FROM storage_rules r JOIN storage_backends b ON b.id = r.backend_id
		 ORDER BY r.priority, r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StorageRule
	for rows.Next() {
		var r StorageRule
		if err := rows.Scan(&r.ID, &r.Pattern, &r.Backend, &r.Priority); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *DB) AddStorageRule(ctx context.Context, pattern, backend string, priority int) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("a rule needs a pattern")
	}
	b, err := d.GetStorageBackend(ctx, backend)
	if err != nil {
		return fmt.Errorf("no storage backend named %q", backend)
	}
	_, err = d.ExecContext(ctx,
		`INSERT INTO storage_rules (pattern, backend_id, priority, created_at) VALUES (?,?,?,?)`,
		strings.TrimSpace(pattern), b.ID, priority, nowStr())
	return err
}

func (d *DB) DeleteStorageRule(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM storage_rules WHERE id = ?`, id)
	return err
}

// SetStorageRulePriority reorders a rule, which is what decides precedence when
// two patterns both match.
func (d *DB) SetStorageRulePriority(ctx context.Context, id int64, priority int) error {
	_, err := d.ExecContext(ctx,
		`UPDATE storage_rules SET priority = ? WHERE id = ?`, priority, id)
	return err
}

// ---------------------------------------------------------------- placement

// RecordRepoStorage notes where a repository's blobs actually are.
func (d *DB) RecordRepoStorage(ctx context.Context, repoID int64, backend string) error {
	_, err := d.ExecContext(ctx, `INSERT INTO repository_storage
		(repo_id, backend, updated_at) VALUES (?,?,?)
		ON CONFLICT(repo_id) DO UPDATE SET backend = excluded.backend, updated_at = excluded.updated_at`,
		repoID, backend, nowStr())
	return err
}

// RepoStorage reports where a repository's blobs were last written, which is
// not always where the rules now say they belong.
func (d *DB) RepoStorage(ctx context.Context, repoID int64) (string, bool) {
	var b string
	if err := d.QueryRowContext(ctx,
		`SELECT backend FROM repository_storage WHERE repo_id = ?`, repoID).Scan(&b); err != nil {
		return "", false
	}
	return b, true
}

// MisplacedRepos lists repositories whose recorded storage differs from what
// the rules would choose now, which is exactly the set needing a migration.
func (d *DB) MisplacedRepos(ctx context.Context, resolve func(string) string) ([]string, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT rep.name, COALESCE(rs.backend, '')
		  FROM repositories rep LEFT JOIN repository_storage rs ON rs.repo_id = rep.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, recorded string
		if err := rows.Scan(&name, &recorded); err != nil {
			return nil, err
		}
		// A repository with nothing recorded has never had a blob written, so
		// there is nothing to move.
		if recorded == "" {
			continue
		}
		if want := resolve(name); want != "" && want != recorded {
			out = append(out, name)
		}
	}
	return out, rows.Err()
}
