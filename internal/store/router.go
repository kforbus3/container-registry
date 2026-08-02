package store

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Routing blobs to a backend by repository.
//
// One registry can hold content that must not share storage: an export-
// controlled namespace belongs in a GovCloud bucket, a partner namespace in a
// commercial one, scratch work on local disk. So the backend is a property of
// the repository rather than of the registry, chosen by the first rule whose
// pattern matches the repository name.
//
// The routing key is the repository, not the user who pushed. If it followed
// the actor, one repository would end up with layers in several buckets
// depending on who happened to push them -- and the residency boundary would
// track people rather than content, which is the opposite of what it is for.

// DefaultBackend is the name a rule uses to mean the fallback backend, which
// has no entry of its own in the backend map.
const DefaultBackend = "default"

// Rule maps a repository name pattern onto a backend. Rules are ordered and the
// first match wins, so specific patterns are placed above general ones.
type Rule struct {
	ID       int64
	Pattern  string
	Backend  string // the backend's operator-facing name
	Priority int
}

// Router resolves a repository name to the backend its blobs live in.
type Router struct {
	mu       sync.RWMutex
	rules    []Rule
	backends map[string]Backend
	fallback Backend
	// placements records where each repository's blobs actually are, which is
	// not always where the rules now say they belong.
	placements map[string]string
	// mirrors holds, per repository, a second backend that writes are copied
	// to while that repository is being migrated.
	mirrors map[string]Backend
	// fallbackName is what the default backend is called in the UI and logs.
	fallbackName string
}

// NewRouter creates a router that sends everything to one backend, which is the
// behaviour of a registry with no rules configured.
func NewRouter(fallback Backend) *Router {
	return &Router{
		backends:     map[string]Backend{},
		placements:   map[string]string{},
		mirrors:      map[string]Backend{},
		fallback:     fallback,
		fallbackName: "default",
	}
}

// Replace swaps in a new rule set and backend map atomically. Anything not
// matched by a rule continues to the fallback.
func (r *Router) Replace(rules []Rule, backends map[string]Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = rules
	r.backends = backends
}

// SetFallback changes the backend used by repositories no rule matches.
func (r *Router) SetFallback(b Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = b
}

// Fallback returns the default backend.
func (r *Router) Fallback() Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fallback
}

// SetPlacements replaces the record of where repositories' blobs actually are.
func (r *Router) SetPlacements(p map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.placements = p
}

// SetPlacement records where one repository's blobs went.
func (r *Router) SetPlacement(repo, backend string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.placements == nil {
		r.placements = map[string]string{}
	}
	r.placements[repo] = backend
}

// Placement reports where a repository's blobs were last written.
func (r *Router) Placement(repo string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.placements[repo]
	return b, ok
}

// SetMirror starts copying one repository's writes to a second backend, which
// is what keeps a push landing mid-migration from being lost at the switch.
func (r *Router) SetMirror(repo string, b Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mirrors == nil {
		r.mirrors = map[string]Backend{}
	}
	r.mirrors[repo] = b
}

// ClearMirror stops mirroring a repository's writes.
func (r *Router) ClearMirror(repo string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.mirrors, repo)
}

// Mirror returns the backend a repository's writes are being copied to, if any.
func (r *Router) Mirror(repo string) Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mirrors[repo]
}

// Resolve reports which backend a repository's blobs are read from and written
// to.
//
// Once a repository has content, that is wherever the content already is --
// never what a rule added afterwards says. A rule change that silently
// redirected reads would 404 every image the repository already held, and a
// rule change that redirected only writes would split one repository across two
// buckets. Both are worse than leaving it where it is until an explicit
// migration moves it; the difference is surfaced as "misplaced" instead.
func (r *Router) Resolve(repo string) (Backend, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if placed, ok := r.placements[repo]; ok && placed != "" {
		if placed == r.fallback.Name() {
			return r.fallback, "placed"
		}
		for _, b := range r.backends {
			if b != nil && b.Name() == placed {
				return b, "placed"
			}
		}
		// The backend it was written to is gone. Failing is the only honest
		// answer: the bytes are not anywhere this registry can currently read.
		return nil, "placed:" + placed
	}
	return r.target(repo)
}

// Target reports where the rules say a repository's blobs belong, ignoring
// where they currently are. This is what a migration aims at.
func (r *Router) Target(repo string) (Backend, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.target(repo)
}

// target is the rule-based answer. Callers hold the lock.
func (r *Router) target(repo string) (Backend, string) {
	for _, rule := range r.rules {
		if !matchPattern(rule.Pattern, repo) {
			continue
		}
		// A rule may name the default explicitly, which is how a namespace is
		// sent back to local storage while a broader rule still routes its
		// siblings elsewhere.
		if rule.Backend == DefaultBackend {
			return r.fallback, rule.Pattern
		}
		if b, ok := r.backends[rule.Backend]; ok && b != nil {
			return b, rule.Pattern
		}
		// A rule naming a backend that no longer exists must not silently fall
		// through to the default: that is how content ends up in the wrong
		// bucket. Stop at the first match and let the caller fail.
		return nil, rule.Pattern
	}
	return r.fallback, ""
}

// Rules returns the current rule set.
func (r *Router) Rules() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rule, len(r.rules))
	copy(out, r.rules)
	return out
}

// Backends returns the named backends currently loaded.
func (r *Router) Backends() map[string]Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]Backend, len(r.backends))
	for k, v := range r.backends {
		out[k] = v
	}
	return out
}

// SameBackend reports whether two repositories share storage. Cross-repository
// blob mounting is only legitimate when they do: mounting across a boundary
// would publish a blob into a repository whose bucket never received the bytes,
// which is both a broken pull and, where the boundary is a jurisdiction, a
// residency violation.
func (r *Router) SameBackend(a, b string) bool {
	ba, _ := r.Resolve(a)
	bb, _ := r.Resolve(b)
	if ba == nil || bb == nil {
		return false
	}
	return ba.Name() == bb.Name()
}

// matchPattern matches a repository name against a rule pattern.
//
// Patterns are globs over the whole name, where '*' spans any run of characters
// including '/', so "gov/*" covers "gov/team/app". A bare "*" is the catch-all.
func matchPattern(pattern, name string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	return globMatch(pattern, name)
}

// globMatch is an iterative backtracking matcher: linear in the common case,
// and unlike a recursive version it cannot blow the stack on a pathological
// pattern supplied by an operator.
func globMatch(pattern, s string) bool {
	var pi, si, star, mark = 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = si
			pi++
		case star != -1:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// Helpers for collection, which works across every backend rather than through
// any one repository.

// AllBackends returns every backend blobs could be in, keyed by name, including
// the default. Collection has to walk all of them: a bucket with no rule
// pointing at it any more still holds the blobs it was given.
func (s *Store) AllBackends() map[string]Backend {
	out := map[string]Backend{}
	for _, b := range s.router.Backends() {
		if b != nil {
			out[b.Name()] = b
		}
	}
	if f := s.router.Fallback(); f != nil {
		out[f.Name()] = f
	}
	return out
}

// WalkBlobsIn enumerates the content-addressed blobs of one backend, decoding
// each key back into the digest it encodes.
func WalkBlobsIn(ctx context.Context, b Backend, fn func(digest string, size int64, mtime time.Time) error) error {
	return b.Walk(ctx, "", func(info ObjectInfo) error {
		algo, hex := keyDigest(info.Key)
		if algo == "" {
			return nil // not a blob key; leave it alone
		}
		return fn(algo+":"+hex, info.Size, info.Modified)
	})
}

// DeleteBlobIn removes one blob from a specific backend.
func DeleteBlobIn(ctx context.Context, b Backend, digest string) error {
	key, err := blobKey(digest)
	if err != nil {
		return err
	}
	return b.Delete(ctx, key)
}
