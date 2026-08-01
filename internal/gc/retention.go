package gc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
)

// Retention removes tags a repository's rules say are no longer wanted. It only
// ever deletes tags; the blobs behind them are freed by garbage collection,
// which keeps "what to keep" and "what to erase" as separate decisions.
type Retention struct {
	DB *db.DB
}

// TagDecision explains what a sweep would do to one tag, so a dry run can be
// read and argued with before anything is deleted.
type TagDecision struct {
	Repository string    `json:"repository"`
	Tag        string    `json:"tag"`
	Digest     string    `json:"digest"`
	Delete     bool      `json:"delete"`
	Reason     string    `json:"reason"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// RetentionResult summarises a sweep.
type RetentionResult struct {
	DryRun       bool          `json:"dry_run"`
	Repositories int           `json:"repositories"`
	TagsExamined int           `json:"tags_examined"`
	TagsDeleted  int           `json:"tags_deleted"`
	Protected    int           `json:"protected"`
	Decisions    []TagDecision `json:"decisions,omitempty"`
	Errors       []string      `json:"errors,omitempty"`
}

// ApplyAll sweeps every repository that has rules.
func (r *Retention) ApplyAll(ctx context.Context, dryRun bool) (*RetentionResult, error) {
	byRepo, err := r.DB.AllRetentionRules(ctx)
	if err != nil {
		return nil, err
	}
	out := &RetentionResult{DryRun: dryRun}
	if len(byRepo) == 0 {
		return out, nil
	}
	repos, err := r.DB.ListRepositories(ctx)
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		rules, ok := byRepo[repo.ID]
		if !ok || len(rules) == 0 {
			continue
		}
		res, err := r.apply(ctx, repo, rules, dryRun)
		if err != nil {
			out.Errors = append(out.Errors, repo.Name+": "+err.Error())
			continue
		}
		out.Repositories++
		out.TagsExamined += res.TagsExamined
		out.TagsDeleted += res.TagsDeleted
		out.Protected += res.Protected
		out.Decisions = append(out.Decisions, res.Decisions...)
	}
	return out, nil
}

// Apply sweeps a single repository.
func (r *Retention) Apply(ctx context.Context, repo *db.Repository, dryRun bool) (*RetentionResult, error) {
	rules, err := r.DB.RetentionRules(ctx, repo.ID)
	if err != nil {
		return nil, err
	}
	enabled := rules[:0]
	for _, rule := range rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return r.apply(ctx, repo, enabled, dryRun)
}

func (r *Retention) apply(ctx context.Context, repo *db.Repository,
	rules []*db.RetentionRule, dryRun bool) (*RetentionResult, error) {

	tags, err := r.DB.ListTagsDetailed(ctx, repo.ID)
	if err != nil {
		return nil, err
	}
	out := &RetentionResult{DryRun: dryRun, Repositories: 1, TagsExamined: len(tags)}
	if len(tags) == 0 || len(rules) == 0 {
		return out, nil
	}

	// Protection is evaluated first and wins over everything: a rule that would
	// delete a protected tag is simply not applied to it.
	protected := map[string]bool{}
	for _, rule := range rules {
		if rule.Kind != db.RetentionProtect {
			continue
		}
		for _, t := range tags {
			if matchPattern(rule.Pattern, t.Name) {
				protected[t.Name] = true
			}
		}
	}

	// Newest first, so "keep the last N" is the first N.
	sorted := make([]*db.Tag, len(tags))
	copy(sorted, tags)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].UpdatedAt.After(sorted[j].UpdatedAt)
	})

	doomed := map[string]string{} // tag -> reason
	for _, rule := range rules {
		switch rule.Kind {
		case db.RetentionKeepLast:
			if rule.KeepCount <= 0 {
				continue
			}
			kept := 0
			for _, t := range sorted {
				if !matchPattern(rule.Pattern, t.Name) {
					continue
				}
				kept++
				if kept > rule.KeepCount {
					doomed[t.Name] = fmt.Sprintf("keeps only the %d newest matching %q",
						rule.KeepCount, rule.Pattern)
				}
			}

		case db.RetentionMaxAge:
			age := rule.MaxAgeDuration()
			if age <= 0 {
				// A malformed window must not be read as "delete everything".
				continue
			}
			cutoff := time.Now().Add(-age)
			for _, t := range sorted {
				if matchPattern(rule.Pattern, t.Name) && t.UpdatedAt.Before(cutoff) {
					doomed[t.Name] = fmt.Sprintf("not updated in %s", rule.MaxAge)
				}
			}
		}
	}

	for _, t := range sorted {
		reason, condemned := doomed[t.Name]
		switch {
		case protected[t.Name] && condemned:
			out.Protected++
			out.Decisions = append(out.Decisions, TagDecision{
				Repository: repo.Name, Tag: t.Name, Digest: t.Digest,
				Delete: false, Reason: "protected", UpdatedAt: t.UpdatedAt,
			})
		case condemned:
			out.Decisions = append(out.Decisions, TagDecision{
				Repository: repo.Name, Tag: t.Name, Digest: t.Digest,
				Delete: true, Reason: reason, UpdatedAt: t.UpdatedAt,
			})
			if dryRun {
				out.TagsDeleted++
				continue
			}
			if err := r.DB.DeleteTag(ctx, repo.ID, t.Name); err != nil {
				out.Errors = append(out.Errors, repo.Name+":"+t.Name+": "+err.Error())
				continue
			}
			r.DB.Audit(ctx, "retention", "retention.delete_tag", repo.Name, t.Name, reason, "")
			out.TagsDeleted++
		}
	}
	return out, nil
}

// matchPattern matches a tag against a glob, using the same semantics as token
// repository scopes so operators only have to learn one syntax.
func matchPattern(pattern, name string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	for _, p := range strings.Split(pattern, ",") {
		if globMatch(strings.TrimSpace(p), name) {
			return true
		}
	}
	return false
}

// globMatch supports '*' for any run of characters and '?' for exactly one.
func globMatch(pattern, s string) bool {
	var pi, si, star, mark = 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
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
