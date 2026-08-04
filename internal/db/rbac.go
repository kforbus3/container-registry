package db

import (
	"context"
	"time"
)

// Repository roles, in increasing order of privilege.
const (
	RoleRead  = "read"
	RoleWrite = "write"
	RoleAdmin = "admin"
)

// RoleRank orders roles so a comparison can ask "at least this much".
func RoleRank(role string) int {
	switch role {
	case RoleAdmin:
		return 3
	case RoleWrite:
		return 2
	case RoleRead:
		return 1
	}
	return 0
}

// ValidRole reports whether a role name is one this registry understands.
func ValidRole(role string) bool { return RoleRank(role) > 0 }

// RepoGrant gives one user a role on one repository.
type RepoGrant struct {
	RepoID    int64     `json:"repo_id"`
	UserID    int64     `json:"user_id"`
	Username  string    `json:"username,omitempty"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func (d *DB) GrantRepoAccess(ctx context.Context, repoID, userID int64, role string) error {
	_, err := d.ExecContext(ctx, `INSERT INTO repo_grants
		(repo_id, user_id, role, created_at) VALUES (?,?,?,?)
		ON CONFLICT(repo_id, user_id) DO UPDATE SET role = excluded.role`,
		repoID, userID, role, nowStr())
	return err
}

func (d *DB) RevokeRepoAccess(ctx context.Context, repoID, userID int64) error {
	_, err := d.ExecContext(ctx,
		`DELETE FROM repo_grants WHERE repo_id = ? AND user_id = ?`, repoID, userID)
	return err
}

// RepoGrants lists the grants on a repository.
func (d *DB) RepoGrants(ctx context.Context, repoID int64) ([]*RepoGrant, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT g.repo_id, g.user_id, u.username, g.role, g.created_at
		FROM repo_grants g JOIN users u ON u.id = g.user_id
		WHERE g.repo_id = ? ORDER BY u.username`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*RepoGrant{}
	for rows.Next() {
		var g RepoGrant
		var created string
		if err := rows.Scan(&g.RepoID, &g.UserID, &g.Username, &g.Role, &created); err != nil {
			return nil, err
		}
		g.CreatedAt = parseTS(created)
		out = append(out, &g)
	}
	return out, rows.Err()
}

// RepoAccess reports a user's effective role on a repository and whether the
// repository is governed by grants at all.
//
// A repository with no grants is ungoverned and behaves exactly as before, so
// adding this feature changes nothing until somebody writes the first grant.
func (d *DB) RepoAccess(ctx context.Context, repoID, userID int64) (role string, governed bool, err error) {
	var total int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM repo_grants WHERE repo_id = ?`, repoID).Scan(&total); err != nil {
		return "", false, err
	}
	if total == 0 {
		return "", false, nil
	}
	err = d.QueryRowContext(ctx,
		`SELECT role FROM repo_grants WHERE repo_id = ? AND user_id = ?`,
		repoID, userID).Scan(&role)
	if err != nil {
		// Governed, but this user is not named on it.
		return "", true, nil
	}
	return role, true, nil
}

// RepoAccessByName answers the same question as RepoAccess for every governed
// repository at once, keyed by repository name.
//
// Listing endpoints need the answer for a whole page. Asking per repository
// would be a query each; grants are few, so reading them all and indexing them
// in memory is both simpler and cheaper.
func (d *DB) RepoAccessByName(ctx context.Context, userID int64) (*RepoAccessIndex, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT r.name, g.user_id, g.role
		FROM repo_grants g JOIN repositories r ON r.id = g.repo_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	idx := &RepoAccessIndex{
		governed: map[string]bool{},
		roles:    map[string]string{},
	}
	for rows.Next() {
		var name, role string
		var uid int64
		if err := rows.Scan(&name, &uid, &role); err != nil {
			return nil, err
		}
		idx.governed[name] = true
		if uid == userID {
			idx.roles[name] = role
		}
	}
	return idx, rows.Err()
}

// RepoAccessIndex is a snapshot of the grants relevant to one user.
type RepoAccessIndex struct {
	governed map[string]bool
	roles    map[string]string
}

// Allows reports whether the user may act on a repository at the given role.
// A repository nobody has granted access to is ungoverned and stays visible,
// which is what keeps the feature opt-in.
func (i *RepoAccessIndex) Allows(name, need string) bool {
	if i == nil || !i.governed[name] {
		return true
	}
	return RoleRank(i.roles[name]) >= RoleRank(need)
}
