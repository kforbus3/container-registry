// Package db owns the SQLite metadata store: users, tokens, repositories,
// manifests, tags, blob references and the audit log. Blob bytes themselves
// live on disk in the content-addressable store (see internal/store).
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

// Open connects to the SQLite database at path, creating it if necessary, and
// applies all migrations.
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite tolerates one writer; the driver serialises but a bounded pool
	// keeps lock contention predictable under concurrent pushes.
	sqldb.SetMaxOpenConns(8)
	sqldb.SetMaxIdleConns(8)
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	d := &DB{sqldb}
	if err := d.migrate(context.Background()); err != nil {
		sqldb.Close()
		return nil, err
	}
	return d, nil
}

// migrations are applied in order; each runs exactly once and is recorded in
// schema_migrations. Never edit an applied migration — append a new one.
var migrations = []struct {
	name string
	stmt string
}{
	{"001_init", `
CREATE TABLE users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT    NOT NULL UNIQUE,
	password_hash TEXT    NOT NULL,
	role          TEXT    NOT NULL DEFAULT 'user',
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    TEXT    NOT NULL,
	last_login_at TEXT
);

CREATE TABLE tokens (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	name          TEXT    NOT NULL,
	user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	prefix        TEXT    NOT NULL UNIQUE,
	secret_hash   TEXT    NOT NULL,
	can_pull      INTEGER NOT NULL DEFAULT 1,
	can_push      INTEGER NOT NULL DEFAULT 0,
	can_delete    INTEGER NOT NULL DEFAULT 0,
	is_admin      INTEGER NOT NULL DEFAULT 0,
	repo_pattern  TEXT    NOT NULL DEFAULT '*',
	created_at    TEXT    NOT NULL,
	expires_at    TEXT,
	last_used_at  TEXT,
	revoked_at    TEXT
);
CREATE INDEX idx_tokens_user ON tokens(user_id);

CREATE TABLE repositories (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL UNIQUE,
	public     INTEGER NOT NULL DEFAULT 0,
	immutable  INTEGER NOT NULL DEFAULT 0,
	description TEXT   NOT NULL DEFAULT '',
	created_at TEXT    NOT NULL,
	updated_at TEXT    NOT NULL
);

CREATE TABLE manifests (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	repo_id       INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
	digest        TEXT    NOT NULL,
	media_type    TEXT    NOT NULL,
	artifact_type TEXT    NOT NULL DEFAULT '',
	subject       TEXT    NOT NULL DEFAULT '',
	size          INTEGER NOT NULL,
	config_digest TEXT    NOT NULL DEFAULT '',
	created_at    TEXT    NOT NULL,
	UNIQUE(repo_id, digest)
);
CREATE INDEX idx_manifests_subject ON manifests(repo_id, subject);

-- Every blob a manifest depends on (config + layers + child manifests), used
-- for reference counting during garbage collection.
CREATE TABLE manifest_refs (
	manifest_id INTEGER NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
	ref_digest  TEXT    NOT NULL,
	kind        TEXT    NOT NULL, -- 'config' | 'layer' | 'manifest'
	size        INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(manifest_id, ref_digest, kind)
);
CREATE INDEX idx_manifest_refs_digest ON manifest_refs(ref_digest);

CREATE TABLE tags (
	repo_id     INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
	name        TEXT    NOT NULL,
	digest      TEXT    NOT NULL,
	created_at  TEXT    NOT NULL,
	updated_at  TEXT    NOT NULL,
	PRIMARY KEY(repo_id, name)
);
CREATE INDEX idx_tags_digest ON tags(repo_id, digest);

-- Blobs that have been fully uploaded and linked into a repository. A blob is
-- only reachable (and only servable) through a repository that mounted it.
CREATE TABLE blobs (
	digest     TEXT    NOT NULL,
	repo_id    INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
	size       INTEGER NOT NULL,
	created_at TEXT    NOT NULL,
	PRIMARY KEY(digest, repo_id)
);
CREATE INDEX idx_blobs_repo ON blobs(repo_id);

CREATE TABLE sessions (
	id         TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT    NOT NULL,
	expires_at TEXT    NOT NULL
);

CREATE TABLE audit_log (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        TEXT NOT NULL,
	actor     TEXT NOT NULL,
	action    TEXT NOT NULL,
	repo      TEXT NOT NULL DEFAULT '',
	reference TEXT NOT NULL DEFAULT '',
	detail    TEXT NOT NULL DEFAULT '',
	remote_ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX idx_audit_repo ON audit_log(repo, ts DESC);

CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`},
}

func (d *DB) migrate(ctx context.Context) error {
	if _, err := d.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	for _, m := range migrations {
		var seen int
		err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, m.name).Scan(&seen)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", m.name, err)
		}
		if seen > 0 {
			continue
		}
		tx, err := d.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.stmt); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(name) VALUES (?)`, m.name); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.name, err)
		}
	}
	return nil
}
