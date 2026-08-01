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

	{"002_vulnerabilities", `
-- One row per image manifest that has been checked against an advisory
-- database. Counts are denormalised so a repository listing does not have to
-- aggregate findings on every page load.
CREATE TABLE vuln_scans (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	repo_id         INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
	manifest_digest TEXT    NOT NULL,
	source          TEXT    NOT NULL,
	status          TEXT    NOT NULL,            -- ok | error
	error           TEXT    NOT NULL DEFAULT '',
	components      INTEGER NOT NULL DEFAULT 0,
	critical        INTEGER NOT NULL DEFAULT 0,
	high            INTEGER NOT NULL DEFAULT 0,
	medium          INTEGER NOT NULL DEFAULT 0,
	low             INTEGER NOT NULL DEFAULT 0,
	unknown         INTEGER NOT NULL DEFAULT 0,
	fixable         INTEGER NOT NULL DEFAULT 0,
	-- Components that no advisory database indexes, so the result can say
	-- "not checked" instead of implying they were checked and found clean.
	unqueryable     INTEGER NOT NULL DEFAULT 0,
	scanned_at      TEXT    NOT NULL,
	UNIQUE(repo_id, manifest_digest)
);
CREATE INDEX idx_vuln_scans_digest ON vuln_scans(manifest_digest);

CREATE TABLE vuln_findings (
	scan_id       INTEGER NOT NULL REFERENCES vuln_scans(id) ON DELETE CASCADE,
	vuln_id       TEXT    NOT NULL,
	purl          TEXT    NOT NULL,
	package       TEXT    NOT NULL,
	version       TEXT    NOT NULL DEFAULT '',
	ecosystem     TEXT    NOT NULL DEFAULT '',
	severity      TEXT    NOT NULL DEFAULT 'UNKNOWN',
	cvss          REAL    NOT NULL DEFAULT 0,
	summary       TEXT    NOT NULL DEFAULT '',
	aliases       TEXT    NOT NULL DEFAULT '',
	fixed_version TEXT    NOT NULL DEFAULT '',
	PRIMARY KEY(scan_id, vuln_id, purl)
);
CREATE INDEX idx_vuln_findings_severity ON vuln_findings(scan_id, severity);

-- Advisory details are shared across every image that contains the affected
-- package, so they are fetched once and reused.
CREATE TABLE vuln_advisories (
	id         TEXT PRIMARY KEY,
	aliases    TEXT NOT NULL DEFAULT '',
	summary    TEXT NOT NULL DEFAULT '',
	severity   TEXT NOT NULL DEFAULT 'UNKNOWN',
	cvss       REAL NOT NULL DEFAULT 0,
	modified   TEXT NOT NULL DEFAULT '',
	fetched_at TEXT NOT NULL
);
`},

	{"003_retention", `
-- Retention rules are per repository. A repository with no rows keeps
-- everything, so the feature is opt-in and an upgrade changes nothing.
CREATE TABLE retention_rules (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	repo_id     INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
	kind        TEXT    NOT NULL,   -- keep_last | delete_older_than | keep_matching
	pattern     TEXT    NOT NULL DEFAULT '*',
	keep_count  INTEGER NOT NULL DEFAULT 0,
	max_age     TEXT    NOT NULL DEFAULT '',
	-- Tags matching a protected pattern are never removed by any rule.
	protect     INTEGER NOT NULL DEFAULT 0,
	enabled     INTEGER NOT NULL DEFAULT 1,
	created_at  TEXT    NOT NULL
);
CREATE INDEX idx_retention_repo ON retention_rules(repo_id);

-- A record of what maintenance actually did, so a scheduled run that deletes
-- something can be explained after the fact.
CREATE TABLE maintenance_runs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	kind          TEXT    NOT NULL,  -- retention | gc
	trigger       TEXT    NOT NULL,  -- schedule | manual
	dry_run       INTEGER NOT NULL DEFAULT 0,
	tags_deleted  INTEGER NOT NULL DEFAULT 0,
	blobs_deleted INTEGER NOT NULL DEFAULT 0,
	bytes_freed   INTEGER NOT NULL DEFAULT 0,
	detail        TEXT    NOT NULL DEFAULT '',
	started_at    TEXT    NOT NULL,
	duration_ms   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_maintenance_started ON maintenance_runs(started_at DESC);
`},

	{"004_webhooks", `
-- A webhook with repo_id NULL fires for the whole registry; otherwise it is
-- scoped to one repository.
CREATE TABLE webhooks (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	repo_id    INTEGER REFERENCES repositories(id) ON DELETE CASCADE,
	name       TEXT    NOT NULL,
	url        TEXT    NOT NULL,
	secret     TEXT    NOT NULL DEFAULT '',
	events     TEXT    NOT NULL DEFAULT '*',
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at TEXT    NOT NULL,
	last_status INTEGER NOT NULL DEFAULT 0,
	last_error  TEXT   NOT NULL DEFAULT '',
	last_sent_at TEXT  NOT NULL DEFAULT ''
);
CREATE INDEX idx_webhooks_repo ON webhooks(repo_id);

-- Delivery history, so a webhook that is not arriving can be diagnosed from
-- the registry rather than from the receiver's logs.
CREATE TABLE webhook_deliveries (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	webhook_id  INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
	event       TEXT    NOT NULL,
	repository  TEXT    NOT NULL DEFAULT '',
	reference   TEXT    NOT NULL DEFAULT '',
	status_code INTEGER NOT NULL DEFAULT 0,
	error       TEXT    NOT NULL DEFAULT '',
	attempts    INTEGER NOT NULL DEFAULT 1,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	sent_at     TEXT    NOT NULL
);
CREATE INDEX idx_deliveries_hook ON webhook_deliveries(webhook_id, id DESC);
`},

	{"005_quotas", `
-- A storage ceiling per repository. Zero or absent means unlimited, so the
-- feature is opt-in and an upgrade changes nothing.
ALTER TABLE repositories ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 0;
`},

	{"006_rbac", `
-- Per-repository access grants. A repository with no grants keeps the previous
-- behaviour exactly: any user who can reach it may use it. Adding the first
-- grant locks the repository down to the people named on it, which makes this
-- opt-in per repository rather than a registry-wide switch.
CREATE TABLE repo_grants (
	repo_id    INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role       TEXT    NOT NULL,   -- read | write | admin
	created_at TEXT    NOT NULL,
	PRIMARY KEY(repo_id, user_id)
);
CREATE INDEX idx_grants_user ON repo_grants(user_id);
`},

	{"007_advisory_documents", `
-- The advisory cache stored only a summary, so a cache hit lost the affected
-- ranges -- and with them the fix version and the ability to check whether an
-- advisory applies to the installed version at all. That made a re-scan report
-- different results from the first scan. Keeping the document makes a cache hit
-- and a fresh fetch produce identical findings.
ALTER TABLE vuln_advisories ADD COLUMN document TEXT NOT NULL DEFAULT '';
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
