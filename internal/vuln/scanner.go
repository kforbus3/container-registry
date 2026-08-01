package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/store"
)

// sbomMediaType is the artifactType the SBOM generator publishes under. The
// scanner reads those documents rather than the image, so it never has to
// decompress a layer.
const sbomMediaType = "application/vnd.cyclonedx+json"

// Job identifies one image manifest to check.
type Job struct {
	RepoID   int64
	RepoName string
	Digest   string
}

// Scanner matches an image's bill of materials against an advisory database.
//
// It deliberately never fails a push or a pull: a scan that cannot reach the
// advisory service records the failure against the image and moves on, because
// an unreachable third party must not stop anyone shipping.
type Scanner struct {
	DB     *db.DB
	Store  *store.Store
	Client *Client
	Log    *slog.Logger

	// AdvisoryTTL is how long a cached advisory is reused before being
	// refetched. Advisories are revised, so this is a freshness bound rather
	// than a permanent cache.
	AdvisoryTTL time.Duration

	// OnComplete, when set, is called after a scan is stored. It is how
	// webhook delivery is chained on without this package knowing about it.
	OnComplete func(repoID int64, repoName, digest string, critical, high int)

	queue chan Job
	wg    sync.WaitGroup

	mu       sync.Mutex
	inflight map[string]bool
	stats    Stats
}

// Stats reports scanner activity since start-up.
type Stats struct {
	Queued   int64 `json:"queued"`
	Scanned  int64 `json:"scanned"`
	Failed   int64 `json:"failed"`
	Skipped  int64 `json:"skipped"`
	Dropped  int64 `json:"dropped"`
	Findings int64 `json:"findings"`
}

func New(database *db.DB, st *store.Store, client *Client, log *slog.Logger, queueDepth int) *Scanner {
	if queueDepth <= 0 {
		queueDepth = 256
	}
	return &Scanner{
		DB: database, Store: st, Client: client, Log: log,
		AdvisoryTTL: 24 * time.Hour,
		queue:       make(chan Job, queueDepth),
		inflight:    map[string]bool{},
	}
}

func (s *Scanner) Start(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-s.queue:
					if !ok {
						return
					}
					s.run(ctx, job)
				}
			}
		}()
	}
}

func (s *Scanner) Wait() { s.wg.Wait() }

func (s *Scanner) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Enqueue schedules an image. It never blocks; a saturated queue drops the job
// and counts it, because scanning must not become backpressure on pushes.
func (s *Scanner) Enqueue(job Job) {
	key := fmt.Sprintf("%d/%s", job.RepoID, job.Digest)
	s.mu.Lock()
	if s.inflight[key] {
		s.mu.Unlock()
		return
	}
	s.inflight[key] = true
	s.stats.Queued++
	s.mu.Unlock()

	select {
	case s.queue <- job:
	default:
		s.mu.Lock()
		delete(s.inflight, key)
		s.stats.Dropped++
		s.mu.Unlock()
		s.Log.Warn("vulnerability queue full, dropping job",
			"repo", job.RepoName, "digest", job.Digest)
	}
}

func (s *Scanner) run(ctx context.Context, job Job) {
	key := fmt.Sprintf("%d/%s", job.RepoID, job.Digest)
	defer func() {
		s.mu.Lock()
		delete(s.inflight, key)
		s.mu.Unlock()
	}()
	defer func() {
		if rec := recover(); rec != nil {
			s.Log.Error("vulnerability scan panicked",
				"repo", job.RepoName, "digest", job.Digest, "panic", rec)
			s.mu.Lock()
			s.stats.Failed++
			s.mu.Unlock()
		}
	}()

	scan, err := s.Scan(ctx, job)
	s.mu.Lock()
	switch {
	case err != nil:
		s.stats.Failed++
	case scan == nil:
		s.stats.Skipped++
	default:
		s.stats.Scanned++
		s.stats.Findings += int64(scan.Total())
	}
	s.mu.Unlock()

	if err != nil {
		s.Log.Error("vulnerability scan failed",
			"repo", job.RepoName, "digest", job.Digest, "err", err)
		return
	}
	if scan != nil && s.OnComplete != nil {
		s.OnComplete(job.RepoID, job.RepoName, job.Digest, scan.Critical, scan.High)
	}
	if scan != nil {
		s.Log.Info("vulnerability scan complete",
			"repo", job.RepoName, "digest", job.Digest,
			"critical", scan.Critical, "high", scan.High,
			"medium", scan.Medium, "low", scan.Low, "fixable", scan.Fixable)
	}
}

// Scan checks one image and stores the result. It returns nil without error
// when the image has no SBOM to work from.
func (s *Scanner) Scan(ctx context.Context, job Job) (*db.VulnScan, error) {
	components, err := s.componentsFor(ctx, job)
	if err != nil {
		return nil, err
	}
	if components == nil {
		return nil, nil // no SBOM yet; nothing to match against
	}

	scan := &db.VulnScan{
		RepoID:         job.RepoID,
		ManifestDigest: job.Digest,
		Source:         s.Client.Endpoint,
		Status:         "ok",
		Components:     len(components),
	}
	if len(components) == 0 {
		// An image with no detectable packages is a real answer, not a failure.
		return scan, s.DB.SaveVulnScan(ctx, scan, nil)
	}

	// Only components that map onto something the database indexes are worth
	// sending. The rest are counted as unqueryable so the result can say so
	// rather than implying they were checked and found clean.
	queries := make([]Query, 0, len(components))
	queried := make([]component, 0, len(components))
	unqueryable := 0
	for _, c := range components {
		q, ok := QueryFor(c.PURL)
		if !ok {
			unqueryable++
			continue
		}
		c.query = q
		queries = append(queries, q)
		queried = append(queried, c)
	}
	scan.Unqueryable = unqueryable
	if len(queries) == 0 {
		return scan, s.DB.SaveVulnScan(ctx, scan, nil)
	}

	matches, err := s.Client.QueryBatch(ctx, queries)
	if err != nil {
		// Record the failure against the image so the UI can say "could not
		// check" rather than implying the image is clean.
		scan.Status = "error"
		scan.Error = err.Error()
		if saveErr := s.DB.SaveVulnScan(ctx, scan, nil); saveErr != nil {
			return nil, saveErr
		}
		return nil, err
	}

	// Collect the distinct advisories referenced, so each is fetched once even
	// when many packages are affected by the same one.
	needed := map[string]bool{}
	for _, ids := range matches {
		for _, id := range ids {
			needed[id] = true
		}
	}
	advisories, err := s.advisories(ctx, needed, matchesNeedingRanges(queried, matches))
	if err != nil {
		return nil, err
	}

	var findings []db.VulnFinding
	seen := map[string]bool{}
	filtered := 0
	for i, ids := range matches {
		if i >= len(queried) {
			break
		}
		c := queried[i]
		for _, id := range ids {
			key := id + "\x00" + c.PURL
			if seen[key] {
				continue
			}
			seen[key] = true

			a, known := advisories[id]

			// Some ecosystems return advisories that do not actually apply to
			// the installed version, so those are verified against the
			// advisory's own ranges before being reported.
			if known && needsRangeCheck(c.query.Ecosystem) {
				if a.Full == nil {
					continue // could not verify; do not assert a problem
				}
				// The epoch lives in a purl qualifier rather than the version
				// string, and it outranks everything else in an RPM comparison.
				m := a.Full.AppliesTo(c.Name, EVRFromPURL(c.PURL), majorOf(purlNamespace(c.PURL)))
				if !m.Applies {
					filtered++
					continue
				}
				a.Fixed = m.Fixed
			}

			f := db.VulnFinding{
				VulnID: id, PURL: c.PURL, Package: c.Name,
				Version: c.Version, Ecosystem: c.Ecosystem,
				Severity: SeverityUnknown,
			}
			if known {
				f.Severity, f.CVSS = a.Severity, a.CVSS
				f.Summary, f.Aliases = a.Summary, a.Aliases
				f.FixedVersion = a.Fixed
			}
			switch f.Severity {
			case SeverityCritical:
				scan.Critical++
			case SeverityHigh:
				scan.High++
			case SeverityMedium:
				scan.Medium++
			case SeverityLow:
				scan.Low++
			default:
				scan.Unknown++
			}
			if f.FixedVersion != "" {
				scan.Fixable++
			}
			findings = append(findings, f)
		}
	}
	if filtered > 0 {
		s.Log.Debug("dropped advisories that do not apply to this release",
			"repo", job.RepoName, "count", filtered)
	}
	if err := s.DB.SaveVulnScan(ctx, scan, findings); err != nil {
		return nil, err
	}
	return scan, nil
}

// matchesNeedingRanges lists the advisories whose full record is required
// because the ecosystem they came from needs a range check.
func matchesNeedingRanges(queried []component, matches [][]string) map[string]bool {
	out := map[string]bool{}
	for i, ids := range matches {
		if i >= len(queried) || !needsRangeCheck(queried[i].query.Ecosystem) {
			continue
		}
		for _, id := range ids {
			out[id] = true
		}
	}
	return out
}

// purlNamespace pulls the distro namespace back out of a package URL.
func purlNamespace(purl string) string {
	p, ok := parsePURL(purl)
	if !ok {
		return ""
	}
	return p.Namespace
}

// resolvedAdvisory is a cached advisory plus the fix version, which is not
// cached because it is specific to the affected package range.
type resolvedAdvisory struct {
	Severity string
	CVSS     float64
	Summary  string
	Aliases  []string
	Fixed    string
	// Full is populated only for advisories that need their affected ranges
	// checked, since holding every record would be wasteful.
	Full *Advisory
}

// advisories resolves detail for each identifier, using the shared cache and
// fetching only what is missing or stale.
func (s *Scanner) advisories(ctx context.Context, ids map[string]bool, needFull map[string]bool) (map[string]resolvedAdvisory, error) {
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	out := make(map[string]resolvedAdvisory, len(list))

	cached, err := s.DB.GetAdvisories(ctx, list, s.AdvisoryTTL)
	if err != nil {
		return nil, err
	}
	for id, a := range cached {
		if needFull[id] {
			continue // the cache holds no ranges, so this one must be fetched
		}
		out[id] = resolvedAdvisory{
			Severity: a.Severity, CVSS: a.CVSS,
			Summary: a.Summary, Aliases: a.Aliases,
		}
	}

	for _, id := range list {
		if _, ok := out[id]; ok {
			continue
		}
		a, err := s.Client.Advisory(ctx, id)
		if err != nil {
			// One unavailable advisory should not sink the whole scan; the
			// finding is still reported, with an unknown severity.
			s.Log.Warn("could not fetch advisory", "id", id, "err", err)
			continue
		}
		severity, score := a.Rating()
		resolved := resolvedAdvisory{
			Severity: severity, CVSS: score,
			Summary: a.Summary, Aliases: a.Aliases, Fixed: a.FixedVersion(),
		}
		if needFull[id] {
			resolved.Full = a
		}
		out[id] = resolved
		if err := s.DB.PutAdvisory(ctx, &db.CachedAdvisory{
			ID: a.ID, Aliases: a.Aliases, Summary: a.Summary,
			Severity: severity, CVSS: score, Modified: a.Modified,
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// component is one entry from the stored bill of materials.
type component struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
	query     Query
}

// componentsFor loads the SBOM published for an image and extracts the package
// URLs worth querying. Returns nil when no SBOM exists.
func (s *Scanner) componentsFor(ctx context.Context, job Job) ([]component, error) {
	sboms, err := s.DB.Referrers(ctx, job.RepoID, job.Digest, sbomMediaType)
	if err != nil {
		return nil, err
	}
	if len(sboms) == 0 {
		return nil, nil
	}
	artBody, err := s.Store.ReadAll(sboms[0].Digest)
	if err != nil {
		return nil, nil
	}
	var art struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(artBody, &art); err != nil || len(art.Layers) == 0 {
		return nil, nil
	}
	docBody, err := s.Store.ReadAll(art.Layers[0].Digest)
	if err != nil {
		return nil, nil
	}

	var doc struct {
		Components []struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			PURL       string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(docBody, &doc); err != nil {
		return nil, fmt.Errorf("parse sbom: %w", err)
	}

	out := make([]component, 0, len(doc.Components))
	seen := map[string]bool{}
	for _, c := range doc.Components {
		// Only a package URL can be matched against an advisory database; a
		// component without one is unidentifiable, not merely unversioned.
		if c.PURL == "" || seen[c.PURL] {
			continue
		}
		seen[c.PURL] = true
		eco := ""
		for _, p := range c.Properties {
			if p.Name == "registry:ecosystem" {
				eco = p.Value
			}
		}
		out = append(out, component{
			Name: c.Name, Version: c.Version, Ecosystem: eco, PURL: c.PURL,
		})
	}
	return out, nil
}
