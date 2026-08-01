package vuln

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
)

// advisoryDoc is a realistic OSV record: the fix version lives inside the
// affected ranges, which is precisely the part a summary-only cache loses.
const advisoryDoc = `{
  "id": "GHSA-test-0001",
  "summary": "Example flaw",
  "aliases": ["CVE-2026-0001"],
  "modified": "2026-01-02T03:04:05Z",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"name": "openssl", "ecosystem": "Alpine:v3.16"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1t-r0"}]}]
  }]
}`

func testScanner(t *testing.T, handler http.Handler) (*Scanner, *db.DB) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	return &Scanner{
		DB:          database,
		Client:      NewClient(srv.URL, 5*time.Second),
		Log:         slog.New(slog.DiscardHandler),
		AdvisoryTTL: time.Hour,
	}, database
}

// TestAdvisoriesCacheHitMatchesFetch is the regression test for a re-scan
// reporting different results from the scan that ran on push. The advisory
// cache held no affected ranges, so the second scan found the same
// vulnerabilities but reported every one of them as unfixable.
func TestAdvisoriesCacheHitMatchesFetch(t *testing.T) {
	var fetches atomic.Int32
	s, _ := testScanner(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(advisoryDoc))
	}))

	ids := map[string]bool{"GHSA-test-0001": true}

	first, err := s.advisories(context.Background(), ids)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	second, err := s.advisories(context.Background(), ids)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}

	if got := fetches.Load(); got != 1 {
		t.Errorf("expected the second resolve to be served from cache, got %d fetches", got)
	}

	a, b := first["GHSA-test-0001"], second["GHSA-test-0001"]
	if a.Fixed == "" {
		t.Fatal("first resolve lost the fix version; the fixture is wrong")
	}
	if b.Fixed != a.Fixed {
		t.Errorf("fix version differs between fetch and cache hit: %q then %q", a.Fixed, b.Fixed)
	}
	if b.Severity != a.Severity || b.CVSS != a.CVSS {
		t.Errorf("severity differs between fetch and cache hit: %s/%v then %s/%v",
			a.Severity, a.CVSS, b.Severity, b.CVSS)
	}
	if b.Full == nil {
		t.Error("cache hit returned no advisory document, so no range check is possible")
	}
}

// TestAdvisoriesLegacyCacheRowRefetches covers rows written before the document
// was cached: they must be treated as misses, not as advisories that happen to
// record no fix.
func TestAdvisoriesLegacyCacheRowRefetches(t *testing.T) {
	var fetches atomic.Int32
	s, database := testScanner(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(advisoryDoc))
	}))

	// A row as the previous schema would have left it: summary fields only.
	if err := database.PutAdvisory(context.Background(), &db.CachedAdvisory{
		ID: "GHSA-test-0001", Summary: "Example flaw", Severity: SeverityHigh, CVSS: 7.5,
	}); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	got, err := s.advisories(context.Background(), map[string]bool{"GHSA-test-0001": true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if fetches.Load() != 1 {
		t.Error("a cache row with no document should be refetched")
	}
	if got["GHSA-test-0001"].Fixed != "1.1.1t-r0" {
		t.Errorf("fix version = %q, want 1.1.1t-r0", got["GHSA-test-0001"].Fixed)
	}
}

// TestPruneAdvisoriesKeepsReferenced checks the sweep that bounds the advisory
// cache: it holds full documents now, so it would otherwise grow without limit.
func TestPruneAdvisoriesKeepsReferenced(t *testing.T) {
	s, database := testScanner(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(advisoryDoc))
	}))
	ctx := context.Background()

	// Two cached advisories, one of which a stored finding refers to.
	if _, err := s.advisories(ctx, map[string]bool{"GHSA-test-0001": true}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := database.PutAdvisory(ctx, &db.CachedAdvisory{
		ID: "GHSA-test-0002", Summary: "unreferenced", Document: []byte(advisoryDoc),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	repo, err := database.EnsureRepository(ctx, "demo/app")
	if err != nil {
		t.Fatalf("ensure repo: %v", err)
	}
	if err := database.SaveVulnScan(ctx, &db.VulnScan{
		RepoID: repo.ID, ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		Status: "ok", Source: "test",
	}, []db.VulnFinding{{VulnID: "GHSA-test-0001", PURL: "pkg:apk/alpine/openssl@1.1.1", Package: "openssl"}}); err != nil {
		t.Fatalf("save scan: %v", err)
	}

	// Nothing is old enough to prune yet.
	if n, err := database.PruneAdvisories(ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("premature prune: n=%d err=%v", n, err)
	}

	n, err := database.PruneAdvisories(ctx, time.Nanosecond)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d advisories, want 1 (the unreferenced one)", n)
	}
	got, err := database.GetAdvisories(ctx, []string{"GHSA-test-0001", "GHSA-test-0002"}, 0)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := got["GHSA-test-0001"]; !ok {
		t.Error("an advisory a finding refers to was pruned")
	}
	if _, ok := got["GHSA-test-0002"]; ok {
		t.Error("the unreferenced advisory survived the prune")
	}
}
