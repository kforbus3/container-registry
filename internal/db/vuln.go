package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// VulnScan is the summary of one image's check against an advisory database.
type VulnScan struct {
	ID             int64     `json:"id"`
	RepoID         int64     `json:"repo_id"`
	ManifestDigest string    `json:"manifest_digest"`
	Source         string    `json:"source"`
	Status         string    `json:"status"`
	Error          string    `json:"error,omitempty"`
	Components     int       `json:"components"`
	Critical       int       `json:"critical"`
	High           int       `json:"high"`
	Medium         int       `json:"medium"`
	Low            int       `json:"low"`
	Unknown        int       `json:"unknown"`
	Fixable        int       `json:"fixable"`
	Unqueryable    int       `json:"unqueryable"`
	ScannedAt      time.Time `json:"scanned_at"`
}

// Total counts every finding regardless of severity.
func (s *VulnScan) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Unknown
}

// VulnFinding is one advisory affecting one package in an image.
type VulnFinding struct {
	VulnID       string   `json:"vuln_id"`
	PURL         string   `json:"purl"`
	Package      string   `json:"package"`
	Version      string   `json:"version,omitempty"`
	Ecosystem    string   `json:"ecosystem,omitempty"`
	Severity     string   `json:"severity"`
	CVSS         float64  `json:"cvss,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Aliases      []string `json:"aliases,omitempty"`
	FixedVersion string   `json:"fixed_version,omitempty"`
}

const vulnScanCols = `id, repo_id, manifest_digest, source, status, error, components,
	critical, high, medium, low, unknown, fixable, unqueryable, scanned_at`

func scanVulnScan(row interface{ Scan(...any) error }) (*VulnScan, error) {
	var s VulnScan
	var ts string
	err := row.Scan(&s.ID, &s.RepoID, &s.ManifestDigest, &s.Source, &s.Status, &s.Error,
		&s.Components, &s.Critical, &s.High, &s.Medium, &s.Low, &s.Unknown, &s.Fixable,
		&s.Unqueryable, &ts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	s.ScannedAt = parseTS(ts)
	return &s, nil
}

// SaveVulnScan replaces any previous result for the manifest, so a re-scan
// against updated advisories supersedes the old answer rather than accumulating.
func (d *DB) SaveVulnScan(ctx context.Context, s *VulnScan, findings []VulnFinding) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM vuln_scans WHERE repo_id = ? AND manifest_digest = ?`,
		s.RepoID, s.ManifestDigest); err != nil {
		return err
	}
	now := nowStr()
	res, err := tx.ExecContext(ctx, `INSERT INTO vuln_scans
		(repo_id, manifest_digest, source, status, error, components,
		 critical, high, medium, low, unknown, fixable, unqueryable, scanned_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.RepoID, s.ManifestDigest, s.Source, s.Status, s.Error, s.Components,
		s.Critical, s.High, s.Medium, s.Low, s.Unknown, s.Fixable, s.Unqueryable, now)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	s.ID, s.ScannedAt = id, parseTS(now)

	for _, f := range findings {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO vuln_findings
			(scan_id, vuln_id, purl, package, version, ecosystem, severity, cvss,
			 summary, aliases, fixed_version)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			id, f.VulnID, f.PURL, f.Package, f.Version, f.Ecosystem, f.Severity, f.CVSS,
			f.Summary, strings.Join(f.Aliases, ","), f.FixedVersion); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) GetVulnScan(ctx context.Context, repoID int64, digest string) (*VulnScan, error) {
	return scanVulnScan(d.QueryRowContext(ctx,
		`SELECT `+vulnScanCols+` FROM vuln_scans WHERE repo_id = ? AND manifest_digest = ?`,
		repoID, digest))
}

// VulnFindings returns an image's findings worst-first, so the caller does not
// have to sort to show the thing that matters most.
func (d *DB) VulnFindings(ctx context.Context, scanID int64) ([]VulnFinding, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT vuln_id, purl, package, version, ecosystem, severity, cvss,
		       summary, aliases, fixed_version
		FROM vuln_findings WHERE scan_id = ?
		ORDER BY CASE severity
			WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
			WHEN 'LOW' THEN 3 ELSE 4 END, cvss DESC, package, vuln_id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []VulnFinding{}
	for rows.Next() {
		var f VulnFinding
		var aliases string
		if err := rows.Scan(&f.VulnID, &f.PURL, &f.Package, &f.Version, &f.Ecosystem,
			&f.Severity, &f.CVSS, &f.Summary, &aliases, &f.FixedVersion); err != nil {
			return nil, err
		}
		if aliases != "" {
			f.Aliases = strings.Split(aliases, ",")
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// VulnScansForRepo returns scan summaries keyed by manifest digest, so a
// repository listing can show severity counts without a query per tag.
func (d *DB) VulnScansForRepo(ctx context.Context, repoID int64) (map[string]*VulnScan, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+vulnScanCols+` FROM vuln_scans WHERE repo_id = ?`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]*VulnScan{}
	for rows.Next() {
		s, err := scanVulnScan(rows)
		if err != nil {
			return nil, err
		}
		out[s.ManifestDigest] = s
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- advisory cache

// CachedAdvisory holds the shared detail for one vulnerability.
type CachedAdvisory struct {
	ID        string
	Aliases   []string
	Summary   string
	Severity  string
	CVSS      float64
	Modified  string
	FetchedAt time.Time
}

// GetAdvisories loads cached advisories by identifier. Entries older than maxAge
// are omitted so they get refetched: advisories are revised, and a severity that
// was medium last month may be critical today.
func (d *DB) GetAdvisories(ctx context.Context, ids []string, maxAge time.Duration) (map[string]*CachedAdvisory, error) {
	out := map[string]*CachedAdvisory{}
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := d.QueryContext(ctx,
		`SELECT id, aliases, summary, severity, cvss, modified, fetched_at
		 FROM vuln_advisories WHERE id IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cutoff := time.Now().Add(-maxAge)
	for rows.Next() {
		var a CachedAdvisory
		var aliases, fetched string
		if err := rows.Scan(&a.ID, &aliases, &a.Summary, &a.Severity, &a.CVSS,
			&a.Modified, &fetched); err != nil {
			return nil, err
		}
		a.FetchedAt = parseTS(fetched)
		if maxAge > 0 && a.FetchedAt.Before(cutoff) {
			continue
		}
		if aliases != "" {
			a.Aliases = strings.Split(aliases, ",")
		}
		out[a.ID] = &a
	}
	return out, rows.Err()
}

func (d *DB) PutAdvisory(ctx context.Context, a *CachedAdvisory) error {
	_, err := d.ExecContext(ctx, `INSERT INTO vuln_advisories
		(id, aliases, summary, severity, cvss, modified, fetched_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			aliases = excluded.aliases, summary = excluded.summary,
			severity = excluded.severity, cvss = excluded.cvss,
			modified = excluded.modified, fetched_at = excluded.fetched_at`,
		a.ID, strings.Join(a.Aliases, ","), a.Summary, a.Severity, a.CVSS,
		a.Modified, nowStr())
	return err
}

// VulnStats aggregates findings across the whole registry for the dashboard.
type VulnStats struct {
	Scanned  int `json:"scanned"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Failed   int `json:"failed"`
}

func (d *DB) VulnStats(ctx context.Context) (*VulnStats, error) {
	var s VulnStats
	err := d.QueryRowContext(ctx, `SELECT
		COUNT(*),
		COALESCE(SUM(critical),0), COALESCE(SUM(high),0),
		COALESCE(SUM(medium),0), COALESCE(SUM(low),0),
		COALESCE(SUM(CASE WHEN status <> 'ok' THEN 1 ELSE 0 END),0)
		FROM vuln_scans`).Scan(&s.Scanned, &s.Critical, &s.High, &s.Medium, &s.Low, &s.Failed)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ManifestsMissingVulnScan lists image manifests that have an SBOM but no scan
// result yet, which is what a backfill or a re-scan sweep works through.
func (d *DB) ManifestsMissingVulnScan(ctx context.Context, limit int) ([]struct {
	RepoID   int64
	RepoName string
	Digest   string
}, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.QueryContext(ctx, `
		SELECT m.repo_id, r.name, m.subject
		FROM manifests m
		JOIN repositories r ON r.id = m.repo_id
		WHERE m.artifact_type = 'application/vnd.cyclonedx+json'
		  AND m.subject <> ''
		  AND NOT EXISTS (
			SELECT 1 FROM vuln_scans v
			WHERE v.repo_id = m.repo_id AND v.manifest_digest = m.subject
		  )
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []struct {
		RepoID   int64
		RepoName string
		Digest   string
	}
	for rows.Next() {
		var e struct {
			RepoID   int64
			RepoName string
			Digest   string
		}
		if err := rows.Scan(&e.RepoID, &e.RepoName, &e.Digest); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
