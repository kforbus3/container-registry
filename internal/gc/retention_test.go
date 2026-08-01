package gc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
)

func newRetentionHarness(t *testing.T) (*Retention, *db.DB, *db.Repository) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	repo, err := database.EnsureRepository(context.Background(), "team/app")
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}
	return &Retention{DB: database}, database, repo
}

// seedTag creates a tag whose updated_at is backdated, so age-based rules can
// be exercised without waiting.
func seedTag(t *testing.T, database *db.DB, repo *db.Repository, name string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	sum := sha256.Sum256([]byte(name))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if err := database.PutTag(ctx, repo.ID, name, digest); err != nil {
		t.Fatalf("put tag %s: %v", name, err)
	}
	when := time.Now().Add(-age).UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx,
		`UPDATE tags SET updated_at = ?, created_at = ? WHERE repo_id = ? AND name = ?`,
		when, when, repo.ID, name); err != nil {
		t.Fatalf("backdate %s: %v", name, err)
	}
}

func addRule(t *testing.T, database *db.DB, repo *db.Repository, r *db.RetentionRule) {
	t.Helper()
	r.RepoID = repo.ID
	r.Enabled = true
	if r.Pattern == "" {
		r.Pattern = "*"
	}
	if _, err := database.CreateRetentionRule(context.Background(), r); err != nil {
		t.Fatalf("create rule: %v", err)
	}
}

func remainingTags(t *testing.T, database *db.DB, repo *db.Repository) []string {
	t.Helper()
	names, err := database.TagNames(context.Background(), repo.ID, "", 0)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	return names
}

func TestKeepLastKeepsTheNewest(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	// Oldest first in age terms, so v5 is the most recently updated.
	for i, age := range []time.Duration{5 * time.Hour, 4 * time.Hour, 3 * time.Hour, 2 * time.Hour, time.Hour} {
		seedTag(t, database, repo, string(rune('a'+i)), age)
	}
	addRule(t, database, repo, &db.RetentionRule{Kind: db.RetentionKeepLast, KeepCount: 2})

	res, err := ret.Apply(context.Background(), repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.TagsDeleted != 3 {
		t.Fatalf("deleted %d tags, want 3", res.TagsDeleted)
	}
	got := remainingTags(t, database, repo)
	if len(got) != 2 {
		t.Fatalf("remaining = %v, want the two newest", got)
	}
	// 'd' and 'e' were updated most recently.
	for _, want := range []string{"d", "e"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q should have been kept; remaining = %v", want, got)
		}
	}
}

func TestMaxAgeDeletesOnlyStaleTags(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	seedTag(t, database, repo, "fresh", time.Hour)
	seedTag(t, database, repo, "stale", 72*time.Hour)

	addRule(t, database, repo, &db.RetentionRule{
		Kind: db.RetentionMaxAge, MaxAge: "24h",
	})
	if _, err := ret.Apply(context.Background(), repo, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := remainingTags(t, database, repo)
	if len(got) != 1 || got[0] != "fresh" {
		t.Fatalf("remaining = %v, want only the fresh tag", got)
	}
}

// A malformed retention window must be ignored, not read as "everything has
// expired" — that would delete an entire repository on a typo.
func TestMalformedMaxAgeDeletesNothing(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	seedTag(t, database, repo, "keep", 1000*time.Hour)
	addRule(t, database, repo, &db.RetentionRule{Kind: db.RetentionMaxAge, MaxAge: "banana"})

	res, err := ret.Apply(context.Background(), repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.TagsDeleted != 0 {
		t.Fatalf("deleted %d tags on a malformed window, want 0", res.TagsDeleted)
	}
	if len(remainingTags(t, database, repo)) != 1 {
		t.Fatal("the tag should have survived")
	}
}

// Protection wins over any rule that would otherwise delete the tag.
func TestProtectionOverridesDeletion(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	seedTag(t, database, repo, "prod-1", 500*time.Hour)
	seedTag(t, database, repo, "dev-1", 500*time.Hour)

	addRule(t, database, repo, &db.RetentionRule{Kind: db.RetentionMaxAge, MaxAge: "24h"})
	addRule(t, database, repo, &db.RetentionRule{Kind: db.RetentionProtect, Pattern: "prod-*"})

	res, err := ret.Apply(context.Background(), repo, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Protected != 1 {
		t.Fatalf("protected = %d, want 1", res.Protected)
	}
	got := remainingTags(t, database, repo)
	if len(got) != 1 || got[0] != "prod-1" {
		t.Fatalf("remaining = %v, want only prod-1", got)
	}
}

// A pattern narrows which tags a rule applies to at all.
func TestKeepLastRespectsPattern(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	seedTag(t, database, repo, "nightly-1", 4*time.Hour)
	seedTag(t, database, repo, "nightly-2", 3*time.Hour)
	seedTag(t, database, repo, "nightly-3", 2*time.Hour)
	seedTag(t, database, repo, "release-1", 10*time.Hour)

	addRule(t, database, repo, &db.RetentionRule{
		Kind: db.RetentionKeepLast, Pattern: "nightly-*", KeepCount: 1,
	})
	if _, err := ret.Apply(context.Background(), repo, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := remainingTags(t, database, repo)
	if len(got) != 2 {
		t.Fatalf("remaining = %v, want the newest nightly plus the untouched release", got)
	}
	for _, want := range []string{"nightly-3", "release-1"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q missing from %v", want, got)
		}
	}
}

// A dry run reports what it would do and changes nothing.
func TestDryRunDeletesNothing(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	for i, age := range []time.Duration{5 * time.Hour, 4 * time.Hour, 3 * time.Hour} {
		seedTag(t, database, repo, string(rune('a'+i)), age)
	}
	addRule(t, database, repo, &db.RetentionRule{Kind: db.RetentionKeepLast, KeepCount: 1})

	res, err := ret.Apply(context.Background(), repo, true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.TagsDeleted != 2 {
		t.Fatalf("dry run reported %d deletions, want 2", res.TagsDeleted)
	}
	if len(remainingTags(t, database, repo)) != 3 {
		t.Fatal("a dry run must not delete anything")
	}
	// The decisions have to explain themselves, or the preview is useless.
	for _, d := range res.Decisions {
		if d.Delete && d.Reason == "" {
			t.Errorf("decision for %s gives no reason", d.Tag)
		}
	}
}

// A repository with no rules is left completely alone, so enabling the feature
// registry-wide cannot delete anything by default.
func TestNoRulesMeansNoChanges(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	seedTag(t, database, repo, "ancient", 10000*time.Hour)

	res, err := ret.ApplyAll(context.Background(), false)
	if err != nil {
		t.Fatalf("ApplyAll: %v", err)
	}
	if res.TagsDeleted != 0 {
		t.Fatalf("deleted %d tags with no rules configured", res.TagsDeleted)
	}
	if len(remainingTags(t, database, repo)) != 1 {
		t.Fatal("the tag should have survived")
	}
}

// A disabled rule does nothing.
func TestDisabledRuleIsInert(t *testing.T) {
	ret, database, repo := newRetentionHarness(t)
	seedTag(t, database, repo, "old", 500*time.Hour)

	rule, err := database.CreateRetentionRule(context.Background(), &db.RetentionRule{
		RepoID: repo.ID, Kind: db.RetentionMaxAge, Pattern: "*", MaxAge: "1h", Enabled: false,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := ret.Apply(context.Background(), repo, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(remainingTags(t, database, repo)) != 1 {
		t.Fatal("a disabled rule deleted a tag")
	}

	// Enabling it makes it take effect.
	if err := database.SetRetentionRuleEnabled(context.Background(), repo.ID, rule.ID, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := ret.Apply(context.Background(), repo, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(remainingTags(t, database, repo)) != 0 {
		t.Fatal("the enabled rule should have deleted the stale tag")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "anything", true},
		{"prod-*", "prod-1", true},
		{"prod-*", "dev-1", false},
		{"v?.0", "v1.0", true},
		{"v?.0", "v10.0", false},
		{"nightly-*, release-*", "release-3", true},
		{"nightly-*, release-*", "hotfix-1", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
	}
	for _, c := range cases {
		if got := matchPattern(c.pattern, c.name); got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
