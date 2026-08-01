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
	// fallbackName is what the default backend is called in the UI and logs.
	fallbackName string
}

// NewRouter creates a router that sends everything to one backend, which is the
// behaviour of a registry with no rules configured.
func NewRouter(fallback Backend) *Router {
	return &Router{
		backends:     map[string]Backend{},
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

// Resolve reports which backend stores a repository's blobs, and the name of
// the rule that decided it. An empty rule name means the fallback was used.
func (r *Router) Resolve(repo string) (Backend, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rule := range r.rules {
		if !matchPattern(rule.Pattern, repo) {
			continue
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
