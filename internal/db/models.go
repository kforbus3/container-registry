package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

// ---------------------------------------------------------------- types

type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"` // "admin" | "user"
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`

	PasswordHash string `json:"-"`
}

func (u *User) IsAdmin() bool { return u.Role == "admin" }

type Token struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	UserID      int64      `json:"user_id"`
	Username    string     `json:"username,omitempty"`
	Prefix      string     `json:"prefix"`
	CanPull     bool       `json:"can_pull"`
	CanPush     bool       `json:"can_push"`
	CanDelete   bool       `json:"can_delete"`
	IsAdmin     bool       `json:"is_admin"`
	RepoPattern string     `json:"repo_pattern"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`

	SecretHash string `json:"-"`
}

// Active reports whether the token may still be used.
func (t *Token) Active() bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return false
	}
	return true
}

type Repository struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Public      bool      `json:"public"`
	Immutable   bool      `json:"immutable"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// QuotaBytes caps how much this repository may store. Zero is unlimited.
	QuotaBytes int64 `json:"quota_bytes"`

	// Populated by ListRepositories.
	TagCount  int   `json:"tag_count"`
	SizeBytes int64 `json:"size_bytes"`
}

type Manifest struct {
	ID           int64     `json:"id"`
	RepoID       int64     `json:"repo_id"`
	Digest       string    `json:"digest"`
	MediaType    string    `json:"media_type"`
	ArtifactType string    `json:"artifact_type,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Size         int64     `json:"size"`
	ConfigDigest string    `json:"config_digest,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type ManifestRef struct {
	Digest string `json:"digest"`
	Kind   string `json:"kind"` // config | layer | manifest
	Size   int64  `json:"size"`
}

type Tag struct {
	Name      string    `json:"name"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Populated by ListTagsDetailed.
	Size      int64  `json:"size,omitempty"`
	MediaType string `json:"media_type,omitempty"`
}

type Session struct {
	ID        string
	UserID    int64
	ExpiresAt time.Time
}

type AuditEntry struct {
	ID        int64     `json:"id"`
	TS        time.Time `json:"ts"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Repo      string    `json:"repo,omitempty"`
	Reference string    `json:"reference,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
}

// ---------------------------------------------------------------- time helpers

const tsLayout = time.RFC3339Nano

func nowStr() string { return time.Now().UTC().Format(tsLayout) }

func parseTS(s string) time.Time {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		// Tolerate values written by older layouts rather than failing a read.
		if t2, err2 := time.Parse(time.RFC3339, s); err2 == nil {
			return t2
		}
		return time.Time{}
	}
	return t
}

func parseNullTS(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := parseTS(s.String)
	return &t
}

func nullTS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(tsLayout)
}

// ---------------------------------------------------------------- users

func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (d *DB) CreateUser(ctx context.Context, username, passwordHash, role string) (*User, error) {
	now := nowStr()
	res, err := d.ExecContext(ctx,
		`INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)`,
		username, passwordHash, role, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, Role: role, CreatedAt: parseTS(now), PasswordHash: passwordHash}, nil
}

const userCols = `id, username, password_hash, role, disabled, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created string
	var last sql.NullString
	var disabled int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &disabled, &created, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.Disabled = disabled != 0
	u.CreatedAt = parseTS(created)
	u.LastLoginAt = parseNullTS(last)
	return &u, nil
}

func (d *DB) GetUserByName(ctx context.Context, username string) (*User, error) {
	return scanUser(d.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username))
}

func (d *DB) GetUser(ctx context.Context, id int64) (*User, error) {
	return scanUser(d.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (d *DB) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (d *DB) SetUserPassword(ctx context.Context, id int64, hash string) error {
	_, err := d.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

func (d *DB) SetUserRole(ctx context.Context, id int64, role string) error {
	_, err := d.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id)
	return err
}

func (d *DB) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := d.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, boolInt(disabled), id)
	return err
}

func (d *DB) DeleteUser(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

func (d *DB) TouchUserLogin(ctx context.Context, id int64) {
	d.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, nowStr(), id)
}

// CountAdmins reports how many enabled admin accounts exist, so the last one
// cannot be deleted, demoted or disabled.
func (d *DB) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------- tokens

const tokenCols = `t.id, t.name, t.user_id, t.prefix, t.secret_hash, t.can_pull, t.can_push,
	t.can_delete, t.is_admin, t.repo_pattern, t.created_at, t.expires_at, t.last_used_at, t.revoked_at`

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var pull, push, del, admin int
	var created string
	var exp, used, revoked sql.NullString
	err := row.Scan(&t.ID, &t.Name, &t.UserID, &t.Prefix, &t.SecretHash, &pull, &push,
		&del, &admin, &t.RepoPattern, &created, &exp, &used, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CanPull, t.CanPush, t.CanDelete, t.IsAdmin = pull != 0, push != 0, del != 0, admin != 0
	t.CreatedAt = parseTS(created)
	t.ExpiresAt, t.LastUsedAt, t.RevokedAt = parseNullTS(exp), parseNullTS(used), parseNullTS(revoked)
	return &t, nil
}

func (d *DB) CreateToken(ctx context.Context, t *Token) (*Token, error) {
	now := nowStr()
	res, err := d.ExecContext(ctx, `INSERT INTO tokens
		(name, user_id, prefix, secret_hash, can_pull, can_push, can_delete, is_admin, repo_pattern, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		t.Name, t.UserID, t.Prefix, t.SecretHash, boolInt(t.CanPull), boolInt(t.CanPush),
		boolInt(t.CanDelete), boolInt(t.IsAdmin), t.RepoPattern, now, nullTS(t.ExpiresAt))
	if err != nil {
		return nil, err
	}
	t.ID, _ = res.LastInsertId()
	t.CreatedAt = parseTS(now)
	return t, nil
}

func (d *DB) GetTokenByPrefix(ctx context.Context, prefix string) (*Token, error) {
	return scanToken(d.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens t WHERE t.prefix = ?`, prefix))
}

func (d *DB) GetToken(ctx context.Context, id int64) (*Token, error) {
	return scanToken(d.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens t WHERE t.id = ?`, id))
}

// ListTokens returns every token, or only those owned by userID when it is non-zero.
func (d *DB) ListTokens(ctx context.Context, userID int64) ([]*Token, error) {
	q := `SELECT ` + tokenCols + `, u.username FROM tokens t JOIN users u ON u.id = t.user_id`
	var args []any
	if userID != 0 {
		q += ` WHERE t.user_id = ?`
		args = append(args, userID)
	}
	q += ` ORDER BY t.created_at DESC`
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		var t Token
		var pull, push, del, admin int
		var created string
		var exp, used, revoked sql.NullString
		err := rows.Scan(&t.ID, &t.Name, &t.UserID, &t.Prefix, &t.SecretHash, &pull, &push,
			&del, &admin, &t.RepoPattern, &created, &exp, &used, &revoked, &t.Username)
		if err != nil {
			return nil, err
		}
		t.CanPull, t.CanPush, t.CanDelete, t.IsAdmin = pull != 0, push != 0, del != 0, admin != 0
		t.CreatedAt = parseTS(created)
		t.ExpiresAt, t.LastUsedAt, t.RevokedAt = parseNullTS(exp), parseNullTS(used), parseNullTS(revoked)
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (d *DB) RevokeToken(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, nowStr(), id)
	return err
}

func (d *DB) DeleteToken(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM tokens WHERE id = ?`, id)
	return err
}

// TouchToken records last use. Failures are ignored: it must never block a request.
func (d *DB) TouchToken(ctx context.Context, id int64) {
	d.ExecContext(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`, nowStr(), id)
}

// ---------------------------------------------------------------- repositories

const repoCols = `id, name, public, immutable, description, quota_bytes, created_at, updated_at`

func scanRepo(row interface{ Scan(...any) error }) (*Repository, error) {
	var r Repository
	var public, immutable int
	var created, updated string
	if err := row.Scan(&r.ID, &r.Name, &public, &immutable, &r.Description,
		&r.QuotaBytes, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.Public, r.Immutable = public != 0, immutable != 0
	r.CreatedAt, r.UpdatedAt = parseTS(created), parseTS(updated)
	return &r, nil
}

func (d *DB) GetRepository(ctx context.Context, name string) (*Repository, error) {
	return scanRepo(d.QueryRowContext(ctx, `SELECT `+repoCols+` FROM repositories WHERE name = ?`, name))
}

// EnsureRepository returns the named repository, creating it if absent.
func (d *DB) EnsureRepository(ctx context.Context, name string) (*Repository, error) {
	if r, err := d.GetRepository(ctx, name); err == nil {
		return r, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := nowStr()
	_, err := d.ExecContext(ctx,
		`INSERT INTO repositories(name, created_at, updated_at) VALUES (?,?,?)
		 ON CONFLICT(name) DO NOTHING`, name, now, now)
	if err != nil {
		return nil, err
	}
	return d.GetRepository(ctx, name)
}

// ListRepositories returns repositories in name order, annotated with tag count
// and on-disk size (the sum of distinct blobs linked to the repository).
func (d *DB) ListRepositories(ctx context.Context) ([]*Repository, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT r.id, r.name, r.public, r.immutable, r.description, r.quota_bytes,
		       r.created_at, r.updated_at,
		       (SELECT COUNT(*) FROM tags  t WHERE t.repo_id = r.id),
		       (SELECT COALESCE(SUM(b.size),0) FROM blobs b WHERE b.repo_id = r.id)
		FROM repositories r ORDER BY r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Repository
	for rows.Next() {
		var r Repository
		var public, immutable int
		var created, updated string
		if err := rows.Scan(&r.ID, &r.Name, &public, &immutable, &r.Description,
			&r.QuotaBytes, &created, &updated, &r.TagCount, &r.SizeBytes); err != nil {
			return nil, err
		}
		r.Public, r.Immutable = public != 0, immutable != 0
		r.CreatedAt, r.UpdatedAt = parseTS(created), parseTS(updated)
		out = append(out, &r)
	}
	return out, rows.Err()
}

// CatalogNames returns repository names for the /v2/_catalog endpoint, in
// lexical order, starting strictly after `last`. n <= 0 means no limit.
func (d *DB) CatalogNames(ctx context.Context, last string, n int) ([]string, error) {
	q := `SELECT name FROM repositories WHERE name > ? ORDER BY name`
	args := []any{last}
	if n > 0 {
		q += ` LIMIT ?`
		args = append(args, n)
	}
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		names = append(names, s)
	}
	return names, rows.Err()
}

func (d *DB) UpdateRepository(ctx context.Context, id int64, public, immutable bool, description string) error {
	_, err := d.ExecContext(ctx,
		`UPDATE repositories SET public = ?, immutable = ?, description = ?, updated_at = ? WHERE id = ?`,
		boolInt(public), boolInt(immutable), description, nowStr(), id)
	return err
}

// SetRepositoryQuota caps a repository's storage. Zero removes the cap.
func (d *DB) SetRepositoryQuota(ctx context.Context, id int64, quota int64) error {
	_, err := d.ExecContext(ctx,
		`UPDATE repositories SET quota_bytes = ?, updated_at = ? WHERE id = ?`,
		quota, nowStr(), id)
	return err
}

// RepositorySize reports the bytes a repository currently accounts for, which
// is the sum of the distinct blobs linked to it.
func (d *DB) RepositorySize(ctx context.Context, repoID int64) (int64, error) {
	var n int64
	err := d.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(size),0) FROM blobs WHERE repo_id = ?`, repoID).Scan(&n)
	return n, err
}

// TagPage is one page of a repository's tags with their metadata.
type TagPage struct {
	Tags  []*Tag `json:"tags"`
	Total int    `json:"total"`
}

// ListTagsPage returns tags in name order with a bound, so a repository with
// thousands of tags does not have to be rendered in full.
func (d *DB) ListTagsPage(ctx context.Context, repoID int64, search string, limit, offset int) (*TagPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	like := "%" + search + "%"

	page := &TagPage{Tags: []*Tag{}}
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tags WHERE repo_id = ? AND name LIKE ?`,
		repoID, like).Scan(&page.Total); err != nil {
		return nil, err
	}
	rows, err := d.QueryContext(ctx, `
		SELECT t.name, t.digest, t.created_at, t.updated_at,
		       COALESCE(m.media_type,''),
		       COALESCE((SELECT SUM(r.size) FROM manifest_refs r WHERE r.manifest_id = m.id), 0)
		FROM tags t LEFT JOIN manifests m ON m.repo_id = t.repo_id AND m.digest = t.digest
		WHERE t.repo_id = ? AND t.name LIKE ?
		ORDER BY t.name LIMIT ? OFFSET ?`, repoID, like, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t Tag
		var created, updated string
		if err := rows.Scan(&t.Name, &t.Digest, &created, &updated, &t.MediaType, &t.Size); err != nil {
			return nil, err
		}
		t.CreatedAt, t.UpdatedAt = parseTS(created), parseTS(updated)
		page.Tags = append(page.Tags, &t)
	}
	return page, rows.Err()
}

func (d *DB) TouchRepository(ctx context.Context, id int64) {
	d.ExecContext(ctx, `UPDATE repositories SET updated_at = ? WHERE id = ?`, nowStr(), id)
}

func (d *DB) DeleteRepository(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM repositories WHERE id = ?`, id)
	return err
}

// ---------------------------------------------------------------- manifests

const manifestCols = `id, repo_id, digest, media_type, artifact_type, subject, size, config_digest, created_at`

func scanManifest(row interface{ Scan(...any) error }) (*Manifest, error) {
	var m Manifest
	var created string
	err := row.Scan(&m.ID, &m.RepoID, &m.Digest, &m.MediaType, &m.ArtifactType, &m.Subject,
		&m.Size, &m.ConfigDigest, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	m.CreatedAt = parseTS(created)
	return &m, nil
}

// PutManifest inserts (or replaces) a manifest and its reference list atomically.
func (d *DB) PutManifest(ctx context.Context, m *Manifest, refs []ManifestRef) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := nowStr()
	// RETURNING gives the row id on both the insert and the update path.
	// last_insert_rowid() must not be used here: SQLite leaves it untouched
	// when an upsert takes DO UPDATE, so it would hand back the id of some
	// unrelated earlier insert on the same pooled connection.
	//
	// created_at is deliberately not updated, so re-pushing an existing
	// manifest preserves when it first appeared.
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO manifests
		(repo_id, digest, media_type, artifact_type, subject, size, config_digest, created_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(repo_id, digest) DO UPDATE SET
			media_type = excluded.media_type,
			artifact_type = excluded.artifact_type,
			subject = excluded.subject,
			size = excluded.size,
			config_digest = excluded.config_digest
		RETURNING id`,
		m.RepoID, m.Digest, m.MediaType, m.ArtifactType, m.Subject, m.Size, m.ConfigDigest, now).Scan(&id)
	if err != nil {
		return err
	}
	m.ID = id

	if _, err := tx.ExecContext(ctx, `DELETE FROM manifest_refs WHERE manifest_id = ?`, id); err != nil {
		return err
	}
	for _, r := range refs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO manifest_refs(manifest_id, ref_digest, kind, size) VALUES (?,?,?,?)`,
			id, r.Digest, r.Kind, r.Size); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repositories SET updated_at = ? WHERE id = ?`, now, m.RepoID); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) GetManifest(ctx context.Context, repoID int64, digest string) (*Manifest, error) {
	return scanManifest(d.QueryRowContext(ctx,
		`SELECT `+manifestCols+` FROM manifests WHERE repo_id = ? AND digest = ?`, repoID, digest))
}

func (d *DB) ListManifests(ctx context.Context, repoID int64) ([]*Manifest, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+manifestCols+` FROM manifests WHERE repo_id = ? ORDER BY created_at DESC`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Manifest{}
	for rows.Next() {
		m, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) ManifestRefs(ctx context.Context, manifestID int64) ([]ManifestRef, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT ref_digest, kind, size FROM manifest_refs WHERE manifest_id = ? ORDER BY kind, ref_digest`, manifestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ManifestRef{}
	for rows.Next() {
		var r ManifestRef
		if err := rows.Scan(&r.Digest, &r.Kind, &r.Size); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Referrers lists manifests in the repository whose subject is the given digest,
// optionally filtered by artifactType (OCI 1.1 referrers API).
func (d *DB) Referrers(ctx context.Context, repoID int64, subject, artifactType string) ([]*Manifest, error) {
	q := `SELECT ` + manifestCols + ` FROM manifests WHERE repo_id = ? AND subject = ?`
	args := []any{repoID, subject}
	if artifactType != "" {
		q += ` AND artifact_type = ?`
		args = append(args, artifactType)
	}
	q += ` ORDER BY created_at`
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Manifest{}
	for rows.Next() {
		m, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) DeleteManifest(ctx context.Context, repoID int64, digest string) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE repo_id = ? AND digest = ?`, repoID, digest); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM manifests WHERE repo_id = ? AND digest = ?`, repoID, digest); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------------------------------------------------------- tags

func (d *DB) PutTag(ctx context.Context, repoID int64, name, digest string) error {
	now := nowStr()
	_, err := d.ExecContext(ctx, `INSERT INTO tags(repo_id, name, digest, created_at, updated_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(repo_id, name) DO UPDATE SET digest = excluded.digest, updated_at = excluded.updated_at`,
		repoID, name, digest, now, now)
	return err
}

func (d *DB) GetTag(ctx context.Context, repoID int64, name string) (*Tag, error) {
	var t Tag
	var created, updated string
	err := d.QueryRowContext(ctx,
		`SELECT name, digest, created_at, updated_at FROM tags WHERE repo_id = ? AND name = ?`,
		repoID, name).Scan(&t.Name, &t.Digest, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt, t.UpdatedAt = parseTS(created), parseTS(updated)
	return &t, nil
}

// TagNames returns tag names in lexical order for /v2/<name>/tags/list.
// last and n implement the spec's pagination; n <= 0 means no limit.
func (d *DB) TagNames(ctx context.Context, repoID int64, last string, n int) ([]string, error) {
	q := `SELECT name FROM tags WHERE repo_id = ? AND name > ? ORDER BY name`
	args := []any{repoID, last}
	if n > 0 {
		q += ` LIMIT ?`
		args = append(args, n)
	}
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		names = append(names, s)
	}
	return names, rows.Err()
}

// ListTagsDetailed returns tags joined to their manifest metadata, for the web UI.
func (d *DB) ListTagsDetailed(ctx context.Context, repoID int64) ([]*Tag, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT t.name, t.digest, t.created_at, t.updated_at,
		       COALESCE(m.media_type,''),
		       COALESCE((SELECT SUM(r.size) FROM manifest_refs r WHERE r.manifest_id = m.id), 0)
		FROM tags t LEFT JOIN manifests m ON m.repo_id = t.repo_id AND m.digest = t.digest
		WHERE t.repo_id = ? ORDER BY t.name`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Tag{}
	for rows.Next() {
		var t Tag
		var created, updated string
		if err := rows.Scan(&t.Name, &t.Digest, &created, &updated, &t.MediaType, &t.Size); err != nil {
			return nil, err
		}
		t.CreatedAt, t.UpdatedAt = parseTS(created), parseTS(updated)
		out = append(out, &t)
	}
	return out, rows.Err()
}

// TagsForDigest lists tag names pointing at a manifest digest.
func (d *DB) TagsForDigest(ctx context.Context, repoID int64, digest string) ([]string, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT name FROM tags WHERE repo_id = ? AND digest = ? ORDER BY name`, repoID, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) DeleteTag(ctx context.Context, repoID int64, name string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM tags WHERE repo_id = ? AND name = ?`, repoID, name)
	return err
}

// ---------------------------------------------------------------- blobs

// LinkBlob records that repoID may serve the blob. Blob bytes are shared
// globally in the content store; this table is the per-repository ACL.
func (d *DB) LinkBlob(ctx context.Context, repoID int64, digest string, size int64) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO blobs(digest, repo_id, size, created_at) VALUES (?,?,?,?)
		 ON CONFLICT(digest, repo_id) DO UPDATE SET size = excluded.size`,
		digest, repoID, size, nowStr())
	return err
}

// BlobLinked reports whether the repository may serve the blob, and its size.
func (d *DB) BlobLinked(ctx context.Context, repoID int64, digest string) (int64, bool, error) {
	var size int64
	err := d.QueryRowContext(ctx,
		`SELECT size FROM blobs WHERE repo_id = ? AND digest = ?`, repoID, digest).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return size, true, nil
}

// AnyBlobLink returns the size of a blob if any repository links it. Used for
// cross-repository blob mounts.
func (d *DB) AnyBlobLink(ctx context.Context, digest string) (int64, bool, error) {
	var size int64
	err := d.QueryRowContext(ctx, `SELECT size FROM blobs WHERE digest = ? LIMIT 1`, digest).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return size, true, nil
}

func (d *DB) UnlinkBlob(ctx context.Context, repoID int64, digest string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM blobs WHERE repo_id = ? AND digest = ?`, repoID, digest)
	return err
}

// ---------------------------------------------------------------- sessions

func (d *DB) CreateSession(ctx context.Context, id string, userID int64, expires time.Time) error {
	_, err := d.ExecContext(ctx, `INSERT INTO sessions(id, user_id, created_at, expires_at) VALUES (?,?,?,?)`,
		id, userID, nowStr(), expires.UTC().Format(tsLayout))
	return err
}

func (d *DB) GetSession(ctx context.Context, id string) (*Session, error) {
	var s Session
	var exp string
	err := d.QueryRowContext(ctx, `SELECT id, user_id, expires_at FROM sessions WHERE id = ?`, id).
		Scan(&s.ID, &s.UserID, &exp)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.ExpiresAt = parseTS(exp)
	if time.Now().After(s.ExpiresAt) {
		d.DeleteSession(ctx, id)
		return nil, ErrNotFound
	}
	return &s, nil
}

func (d *DB) DeleteSession(ctx context.Context, id string) error {
	_, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (d *DB) PurgeExpiredSessions(ctx context.Context) error {
	_, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, nowStr())
	return err
}

// ---------------------------------------------------------------- audit

// Audit appends an entry. Errors are swallowed: auditing must never fail a request.
func (d *DB) Audit(ctx context.Context, actor, action, repo, reference, detail, ip string) {
	d.ExecContext(ctx,
		`INSERT INTO audit_log(ts, actor, action, repo, reference, detail, remote_ip) VALUES (?,?,?,?,?,?,?)`,
		nowStr(), actor, action, repo, reference, detail, ip)
}

func (d *DB) ListAudit(ctx context.Context, repo string, limit int) ([]*AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, ts, actor, action, repo, reference, detail, remote_ip FROM audit_log`
	var args []any
	if repo != "" {
		q += ` WHERE repo = ?`
		args = append(args, repo)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Repo, &e.Reference, &e.Detail, &e.RemoteIP); err != nil {
			return nil, err
		}
		e.TS = parseTS(ts)
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- settings & stats

func (d *DB) GetSetting(ctx context.Context, key, def string) string {
	var v string
	if err := d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}

type Stats struct {
	Repositories int   `json:"repositories"`
	Tags         int   `json:"tags"`
	Manifests    int   `json:"manifests"`
	Blobs        int   `json:"blobs"`
	Users        int   `json:"users"`
	ActiveTokens int   `json:"active_tokens"`
	SizeBytes    int64 `json:"size_bytes"`
}

func (d *DB) Stats(ctx context.Context) (*Stats, error) {
	var s Stats
	err := d.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM repositories),
		(SELECT COUNT(*) FROM tags),
		(SELECT COUNT(*) FROM manifests),
		(SELECT COUNT(DISTINCT digest) FROM blobs),
		(SELECT COUNT(*) FROM users),
		(SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL),
		(SELECT COALESCE(SUM(size),0) FROM (SELECT DISTINCT digest, size FROM blobs))
	`).Scan(&s.Repositories, &s.Tags, &s.Manifests, &s.Blobs, &s.Users, &s.ActiveTokens, &s.SizeBytes)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ReachableDigests returns every blob digest reachable from a live manifest,
// plus the manifest digests themselves. Garbage collection deletes the rest.
func (d *DB) ReachableDigests(ctx context.Context) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	rows, err := d.QueryContext(ctx, `
		SELECT digest FROM manifests
		UNION
		SELECT r.ref_digest FROM manifest_refs r JOIN manifests m ON m.id = r.manifest_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out[s] = struct{}{}
	}
	return out, rows.Err()
}

// BlobLink identifies one repository's claim on a blob.
type BlobLink struct {
	Digest string
	RepoID int64
}

// FindUnreferencedBlobLinks returns blob links that no manifest in the same
// repository depends on. These are what garbage collection unlinks.
func (d *DB) FindUnreferencedBlobLinks(ctx context.Context) ([]BlobLink, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT b.digest, b.repo_id FROM blobs b
		WHERE NOT EXISTS (
			SELECT 1 FROM manifest_refs r JOIN manifests m ON m.id = r.manifest_id
			WHERE m.repo_id = b.repo_id AND r.ref_digest = b.digest
		) AND NOT EXISTS (
			SELECT 1 FROM manifests m WHERE m.repo_id = b.repo_id AND m.digest = b.digest
		)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dead []BlobLink
	for rows.Next() {
		var l BlobLink
		if err := rows.Scan(&l.Digest, &l.RepoID); err != nil {
			return nil, err
		}
		dead = append(dead, l)
	}
	return dead, rows.Err()
}

// PruneUnreferencedBlobLinks drops blob links no live manifest depends on and
// returns the links that were removed.
func (d *DB) PruneUnreferencedBlobLinks(ctx context.Context) ([]BlobLink, error) {
	dead, err := d.FindUnreferencedBlobLinks(ctx)
	if err != nil {
		return nil, err
	}
	for _, l := range dead {
		if _, err := d.ExecContext(ctx,
			`DELETE FROM blobs WHERE digest = ? AND repo_id = ?`, l.Digest, l.RepoID); err != nil {
			return nil, err
		}
	}
	return dead, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
