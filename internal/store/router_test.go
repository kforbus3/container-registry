package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func namedBackend(t *testing.T, name string) Backend {
	t.Helper()
	b, err := NewFilesystemBackend(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRouterFirstMatchWins(t *testing.T) {
	def := namedBackend(t, "default")
	gov := namedBackend(t, "gov")
	partner := namedBackend(t, "partner")

	r := NewRouter(def)
	r.Replace([]Rule{
		{Pattern: "gov/restricted/*", Backend: "gov", Priority: 1},
		{Pattern: "gov/*", Backend: "gov", Priority: 2},
		{Pattern: "partners/*", Backend: "partner", Priority: 3},
	}, map[string]Backend{"gov": gov, "partner": partner})

	cases := []struct {
		repo string
		want Backend
		rule string
	}{
		{"gov/app", gov, "gov/*"},
		{"gov/restricted/weapons", gov, "gov/restricted/*"},
		{"gov/team/sub/app", gov, "gov/*"}, // '*' spans slashes
		{"partners/acme", partner, "partners/*"},
		{"public/web", def, ""},     // no rule: the fallback
		{"government/app", def, ""}, // prefix must be a path segment
		{"gov", def, ""},            // "gov/*" does not match bare "gov"
	}
	for _, c := range cases {
		got, rule := r.Resolve(c.repo)
		if got != c.want {
			t.Errorf("%s routed to %v, want %v", c.repo, name(got), name(c.want))
		}
		if rule != c.rule {
			t.Errorf("%s matched rule %q, want %q", c.repo, rule, c.rule)
		}
	}
}

// TestRouterMissingBackendDoesNotFallThrough is the important safety property.
// A rule naming a backend that is not loaded must fail, not quietly send
// restricted content to the default bucket.
func TestRouterMissingBackendDoesNotFallThrough(t *testing.T) {
	def := namedBackend(t, "default")
	r := NewRouter(def)
	r.Replace([]Rule{{Pattern: "gov/*", Backend: "govcloud"}}, map[string]Backend{})

	got, rule := r.Resolve("gov/app")
	if got != nil {
		t.Errorf("gov/app fell through to %s; it must fail instead", name(got))
	}
	if rule != "gov/*" {
		t.Errorf("rule reported as %q, want gov/*", rule)
	}
	// Repositories the broken rule does not cover are unaffected.
	if b, _ := r.Resolve("public/web"); b != def {
		t.Error("an unrelated repository stopped resolving")
	}
}

// TestSameBackendGuardsMounting covers cross-repository blob mounting, which is
// only legitimate within one backend.
func TestSameBackendGuardsMounting(t *testing.T) {
	def := namedBackend(t, "default")
	gov := namedBackend(t, "gov")
	r := NewRouter(def)
	r.Replace([]Rule{{Pattern: "gov/*", Backend: "gov"}}, map[string]Backend{"gov": gov})

	if !r.SameBackend("public/a", "public/b") {
		t.Error("two default repositories should share a backend")
	}
	if !r.SameBackend("gov/a", "gov/b") {
		t.Error("two gov repositories should share a backend")
	}
	if r.SameBackend("gov/a", "public/b") {
		t.Error("mounting across a storage boundary must not be allowed")
	}
	// An unresolvable repository is never mountable.
	r.Replace([]Rule{{Pattern: "broken/*", Backend: "missing"}}, map[string]Backend{})
	if r.SameBackend("broken/a", "broken/b") {
		t.Error("an unresolvable repository must not be treated as mountable")
	}
}

func TestRouterCatchAll(t *testing.T) {
	def := namedBackend(t, "default")
	other := namedBackend(t, "other")
	r := NewRouter(def)
	r.Replace([]Rule{{Pattern: "*", Backend: "other"}}, map[string]Backend{"other": other})
	if b, rule := r.Resolve("anything/at/all"); b != other || rule != "*" {
		t.Errorf("catch-all did not apply: %s via %q", name(b), rule)
	}
}

func name(b Backend) string {
	if b == nil {
		return "<nil>"
	}
	return b.Name()
}

// TestPlacementSurvivesRuleChange is the regression test for a rule change
// breaking every repository it matched. Adding a rule must not redirect reads
// of content that is already somewhere else: the bytes do not move with the
// rule, so following it would 404 every image the repository already held.
func TestPlacementSurvivesRuleChange(t *testing.T) {
	def := namedBackend(t, "default")
	archive := namedBackend(t, "archive")
	r := NewRouter(def)

	// A repository whose blobs were written to the default backend.
	r.SetPlacement("public/web", def.Name())

	// Later, a rule says that namespace belongs in the archive backend.
	r.Replace([]Rule{{Pattern: "public/*", Backend: "archive"}},
		map[string]Backend{"archive": archive})

	got, why := r.Resolve("public/web")
	if got != def {
		t.Errorf("reads redirected to %s; they must stay with the bytes in %s",
			name(got), name(def))
	}
	if why != "placed" {
		t.Errorf("resolution reason %q, want \"placed\"", why)
	}
	// The rules still say where it ought to end up, which is what a migration
	// aims at and what marks it misplaced.
	if target, _ := r.Target("public/web"); target != archive {
		t.Errorf("target is %s, want %s", name(target), name(archive))
	}
	// A repository with no content yet follows the rule immediately.
	if b, _ := r.Resolve("public/brand-new"); b != archive {
		t.Errorf("a repository with no blobs routed to %s, want %s", name(b), name(archive))
	}
}

// TestPlacementToMissingBackendFails covers a backend that has been removed
// from under content that still lives in it.
func TestPlacementToMissingBackendFails(t *testing.T) {
	def := namedBackend(t, "default")
	r := NewRouter(def)
	r.SetPlacement("orphan/app", "s3(https://gone.example/bucket)")
	if b, why := r.Resolve("orphan/app"); b != nil {
		t.Errorf("resolved to %s; the bytes are not readable from anywhere configured", name(b))
	} else if !strings.HasPrefix(why, "placed:") {
		t.Errorf("reason %q does not say where it was placed", why)
	}
}
