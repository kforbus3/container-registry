package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/store"
)

// Managing named backends and the rules that route repositories to them.

// LoadRouting rebuilds the router from the database. It is called at start-up
// and after any change, so the in-memory table and the stored one never drift.
func (s *Server) LoadRouting(ctx context.Context) error {
	backends, err := s.DB.ListStorageBackends(ctx)
	if err != nil {
		return err
	}
	key, err := s.configKey()
	if err != nil {
		return err
	}
	live := map[string]store.Backend{}
	for _, b := range backends {
		cfg, ok := store.ParsePersisted(b.Config)
		if !ok {
			s.Log.Error("storage backend has unreadable configuration", "backend", b.Name)
			continue
		}
		built, err := s.buildBackend(cfg, key)
		if err != nil {
			// Loud, and deliberately not fatal: one broken backend must not stop
			// the registry serving everything else. Repositories routed to it
			// fail with a clear error rather than falling back to the default.
			s.Log.Error("storage backend could not be opened", "backend", b.Name, "err", err)
			continue
		}
		live[b.Name] = built
	}

	rules, err := s.DB.ListStorageRules(ctx)
	if err != nil {
		return err
	}
	routed := make([]store.Rule, 0, len(rules))
	for _, r := range rules {
		routed = append(routed, store.Rule{
			ID: r.ID, Pattern: r.Pattern, Backend: r.Backend, Priority: r.Priority,
		})
	}
	s.Store.Router().Replace(routed, live)

	// Repositories that predate placement tracking have content but no record
	// of where it is. Recording it before any rule is consulted is what stops a
	// rule added later from redirecting their reads to an empty bucket.
	if n, err := s.DB.BackfillRepoStorage(ctx, s.Store.Router().Fallback().Name()); err != nil {
		return err
	} else if n > 0 {
		s.Log.Info("recorded storage placement for existing repositories", "count", n)
	}

	// Where blobs actually are, which is what reads and writes follow until a
	// migration moves them.
	placements, err := s.DB.AllRepoStorage(ctx)
	if err != nil {
		return err
	}
	s.Store.Router().SetPlacements(placements)
	if len(routed) > 0 {
		s.Log.Info("storage routing loaded", "rules", len(routed), "backends", len(live))
	}
	return nil
}

// buildBackend turns a stored configuration into a live backend.
func (s *Server) buildBackend(cfg store.PersistedConfig, key []byte) (store.Backend, error) {
	if cfg.Kind == "filesystem" {
		// A named filesystem backend gets its own directory, so two of them are
		// genuinely separate stores rather than aliases for one.
		dir := s.Cfg.DataDir + "/blobs"
		if cfg.Prefix != "" {
			dir = s.Cfg.DataDir + "/blobs-" + cfg.Prefix
		}
		return store.NewFilesystemBackend(dir)
	}
	s3, err := cfg.S3(key)
	if err != nil {
		return nil, err
	}
	return store.NewS3Backend(s3)
}

// handleStorageBackends lists and creates named backends.
func (s *Server) handleStorageBackends(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listBackends(w, r)
	case http.MethodPost:
		s.createBackend(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listBackends(w http.ResponseWriter, r *http.Request) {
	stored, err := s.DB.ListStorageBackends(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list backends")
		return
	}
	live := s.Store.Router().Backends()
	out := make([]map[string]any, 0, len(stored))
	for _, b := range stored {
		cfg, _ := store.ParsePersisted(b.Config)
		entry := map[string]any{
			"name":    b.Name,
			"kind":    cfg.Kind,
			"healthy": live[b.Name] != nil,
		}
		if cfg.Kind == "s3" {
			entry["endpoint"] = cfg.Endpoint
			entry["bucket"] = cfg.Bucket
			entry["region"] = cfg.Region
			entry["prefix"] = cfg.Prefix
			entry["path_style"] = cfg.PathStyle
			entry["access_key"] = maskKey(cfg.AccessKey)
		} else {
			entry["prefix"] = cfg.Prefix
		}
		if b := live[b.Name]; b != nil {
			entry["backend"] = b.Name()
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"backends": out,
		"default":  s.Store.Router().Fallback().Name(),
	})
}

// createBackend adds a named backend, proving it works before storing it.
func (s *Server) createBackend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		storageRequest
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "a backend needs a name")
		return
	}
	if name == "default" {
		writeErr(w, http.StatusBadRequest, `"default" is reserved for the fallback backend`)
		return
	}

	backend, cfg, err := s.backendFor(r.Context(), req.storageRequest)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if res := probeBackend(r.Context(), backend); !res.OK {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("%s failed the %s check: %s", backend.Name(), res.Stage, res.Error),
			"stage": res.Stage,
		})
		return
	}

	persisted := store.PersistedConfig{Kind: "filesystem", Prefix: req.Prefix}
	if req.Kind == "s3" {
		key, err := s.configKey()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if persisted, err = store.FromS3(cfg, key); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	blob, err := persisted.Marshal()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.DB.SaveStorageBackend(r.Context(), name, blob); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.LoadRouting(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "storage.backend.create", "", "", name+" -> "+backend.Name())
	writeJSON(w, http.StatusCreated, map[string]any{"name": name, "backend": backend.Name()})
}

func (s *Server) handleStorageBackend(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.DB.DeleteStorageBackend(r.Context(), name); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err := s.LoadRouting(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "storage.backend.delete", "", "", name)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// handleStorageRules lists and creates routing rules.
func (s *Server) handleStorageRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules, err := s.DB.ListStorageRules(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not list rules")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"rules":   rules,
			"default": s.Store.Router().Fallback().Name(),
		})
	case http.MethodPost:
		var req struct {
			Pattern  string `json:"pattern"`
			Backend  string `json:"backend"`
			Priority int    `json:"priority"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := s.DB.AddStorageRule(r.Context(), req.Pattern, req.Backend, req.Priority); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.LoadRouting(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r, "storage.rule.create", "", "", req.Pattern+" -> "+req.Backend)
		writeJSON(w, http.StatusCreated, map[string]any{
			"pattern": req.Pattern, "backend": req.Backend,
			"misplaced": s.misplaced(r.Context()),
		})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleStorageRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.DB.DeleteStorageRule(r.Context(), id); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	case http.MethodPatch:
		var req struct {
			Priority int `json:"priority"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := s.DB.SetStorageRulePriority(r.Context(), id, req.Priority); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.LoadRouting(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "storage.rule.update", "", "", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "misplaced": s.misplaced(r.Context())})
}

// misplaced lists repositories whose blobs are not where the rules now say
// they should be. Adding a rule does not move anything, so this is what turns
// "the rule is saved" into "and here is what still has to happen".
func (s *Server) misplaced(ctx context.Context) []string {
	router := s.Store.Router()
	out, err := s.DB.MisplacedRepos(ctx, func(repo string) string {
		b, _ := router.Target(repo)
		if b == nil {
			return ""
		}
		return b.Name()
	})
	if err != nil {
		return nil
	}
	return out
}

// routingView summarises routing for the settings payload.
func (s *Server) routingView(ctx context.Context) map[string]any {
	rules, _ := s.DB.ListStorageRules(ctx)
	backends, _ := s.DB.ListStorageBackends(ctx)
	live := s.Store.Router().Backends()

	names := make([]map[string]any, 0, len(backends))
	for _, b := range backends {
		cfg, _ := store.ParsePersisted(b.Config)
		names = append(names, map[string]any{
			"name": b.Name, "kind": cfg.Kind, "bucket": cfg.Bucket,
			"endpoint": cfg.Endpoint, "healthy": live[b.Name] != nil,
		})
	}
	if rules == nil {
		rules = []db.StorageRule{}
	}
	// The default is offered alongside the named backends so a rule can send a
	// namespace back to local storage without deleting the rule that sent its
	// siblings away.
	names = append(names, map[string]any{
		"name": db.DefaultBackendName, "kind": "default",
		"bucket": "", "endpoint": s.Store.Router().Fallback().Name(), "healthy": true,
	})
	return map[string]any{
		"rules":     rules,
		"backends":  names,
		"default":   s.Store.Router().Fallback().Name(),
		"misplaced": s.misplaced(ctx),
	}
}

// handleRepoMigrate moves one repository's blobs to wherever the rules now say
// they belong.
func (s *Server) handleRepoMigrate(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Moving blobs between backends is an operator action on storage the
	// operator configured, not something a repository's own permissions should
	// reach. Every other storage endpoint is administrator-only; so is this.
	if p := principalFrom(r.Context()); p == nil || !p.Admin {
		writeErr(w, http.StatusForbidden, "administrator privileges required")
		return
	}
	router := s.Store.Router()
	target, rule := router.Target(repo.Name)
	if target == nil {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("rule %q names a backend that is not configured", rule))
		return
	}
	digests, err := s.DB.RepoBlobDigests(r.Context(), repo.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list this repository's blobs")
		return
	}

	err = s.Store.MigrateRepo(context.Background(), repo.Name, target, digests, func(err error) {
		if err != nil {
			s.Log.Error("repository migration failed", "repo", repo.Name, "err", err)
			return
		}
		// Only now does the repository start reading from the new backend. Doing
		// it earlier would point reads at a copy that was not finished.
		ctx := context.Background()
		if dbErr := s.DB.RecordRepoStorage(ctx, repo.ID, target.Name()); dbErr != nil {
			s.Log.Error("migration finished but placement was not recorded",
				"repo", repo.Name, "err", dbErr)
			return
		}
		s.Store.Router().SetPlacement(repo.Name, target.Name())
		s.Log.Info("repository migrated", "repo", repo.Name, "backend", target.Name())
	})
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(r, "storage.repo.migrate", repo.Name, "", target.Name())
	writeJSON(w, http.StatusAccepted, map[string]any{
		"repository": repo.Name,
		"to":         target.Name(),
		"blobs":      len(digests),
	})
}

// repoStorageView reports where one repository's blobs are, where the rules say
// they belong, and the rule that decided it.
//
// A registry with several backends makes "where does this actually live" a
// real question, and the answer is not derivable from anything else on the
// page: two repositories side by side can be in different buckets.
func (s *Server) repoStorageView(repo string) map[string]any {
	router := s.Store.Router()
	actual, why := router.Resolve(repo)
	target, rule := router.Target(repo)

	out := map[string]any{"rule": rule}
	if actual != nil {
		out["backend"] = actual.Name()
	} else {
		// The recorded placement names a backend that is not configured, so the
		// bytes are not readable from anywhere this registry knows about.
		out["backend"] = ""
		out["error"] = "this repository's blobs were written to " +
			strings.TrimPrefix(why, "placed:") + ", which is not configured"
	}
	if target != nil {
		out["target"] = target.Name()
	}
	// Misplaced only means the rules changed after the content was written.
	// Pulls keep working; it is a migration waiting to happen, not a fault.
	out["misplaced"] = actual != nil && target != nil && actual.Name() != target.Name()
	if rule == "" || why == "placed" {
		out["rule"] = ruleFor(router, repo)
	}
	return out
}

// ruleFor names the rule that would place a repository, for display.
func ruleFor(router *store.Router, repo string) string {
	_, rule := router.Target(repo)
	return rule
}

// ---------------------------------------------------------------- move all

// batchMigration tracks moving every misplaced repository, one after another.
//
// Migrations run one at a time by design -- two copies competing for the same
// backend help nobody -- so a batch is a queue rather than a fan-out. Its state
// is separate from the per-repository progress so the UI can show both "3 of 8
// repositories" and how far the current one has got.
type batchMigration struct {
	mu        sync.Mutex
	running   bool
	total     int
	done      int
	current   string
	failures  []string
	startedAt time.Time
	endedAt   time.Time
}

func (b *batchMigration) snapshot() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]any{
		"running": b.running, "total": b.total, "done": b.done,
		"current": b.current, "failures": b.failures,
	}
	if !b.startedAt.IsZero() {
		out["started_at"] = b.startedAt
	}
	if !b.endedAt.IsZero() {
		out["ended_at"] = b.endedAt
	}
	return out
}

// handleMigrateAll moves every misplaced repository to where its rule points.
func (s *Server) handleMigrateAll(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.batch.snapshot())
		return
	}
	if envManaged() {
		writeErr(w, http.StatusConflict, "storage is configured by the environment")
		return
	}
	repos := s.misplaced(r.Context())
	if len(repos) == 0 {
		writeErr(w, http.StatusBadRequest, "every repository is already where the rules say")
		return
	}

	s.batch.mu.Lock()
	if s.batch.running {
		s.batch.mu.Unlock()
		writeErr(w, http.StatusConflict, "a bulk move is already running")
		return
	}
	// Fields are reset individually. Assigning a fresh struct over *s.batch
	// would replace the mutex currently held with a zero-valued one, and the
	// Unlock below would then be unlocking a lock nobody holds -- which is a
	// fatal error in Go, not a recoverable panic, so it takes the registry down.
	s.batch.running = true
	s.batch.total = len(repos)
	s.batch.done = 0
	s.batch.current = ""
	s.batch.failures = nil
	s.batch.startedAt = time.Now()
	s.batch.endedAt = time.Time{}
	s.batch.mu.Unlock()

	s.audit(r, "storage.migrate.all", "", "", fmt.Sprintf("%d repositories", len(repos)))
	go s.runBatch(repos)
	writeJSON(w, http.StatusAccepted, s.batch.snapshot())
}

// runBatch moves each repository in turn, carrying on past one that fails.
//
// A single failure must not strand the rest: the repositories are independent,
// and stopping would leave an operator to work out which of eight were done.
func (s *Server) runBatch(repos []string) {
	ctx := context.Background()
	for _, name := range repos {
		s.batch.mu.Lock()
		s.batch.current = name
		s.batch.mu.Unlock()

		if err := s.migrateOne(ctx, name); err != nil {
			s.Log.Error("bulk move: repository failed", "repo", name, "err", err)
			s.batch.mu.Lock()
			s.batch.failures = append(s.batch.failures, name+": "+err.Error())
			s.batch.mu.Unlock()
		}
		s.batch.mu.Lock()
		s.batch.done++
		s.batch.mu.Unlock()
	}
	s.batch.mu.Lock()
	s.batch.running = false
	s.batch.current = ""
	s.batch.endedAt = time.Now()
	s.batch.mu.Unlock()
	s.Log.Info("bulk storage move finished", "repositories", len(repos))
}

// migrateOne moves a single repository and waits for it to finish, which is
// what makes the batch sequential.
func (s *Server) migrateOne(ctx context.Context, name string) error {
	repo, err := s.DB.GetRepository(ctx, name)
	if err != nil {
		return err
	}
	target, rule := s.Store.Router().Target(name)
	if target == nil {
		return fmt.Errorf("rule %q names a backend that is not configured", rule)
	}
	digests, err := s.DB.RepoBlobDigests(ctx, repo.ID)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	if err := s.Store.MigrateRepo(ctx, name, target, digests, func(err error) {
		done <- err
	}); err != nil {
		return err
	}
	if err := <-done; err != nil {
		return err
	}
	if err := s.DB.RecordRepoStorage(ctx, repo.ID, target.Name()); err != nil {
		return fmt.Errorf("moved, but the new location was not recorded: %w", err)
	}
	s.Store.Router().SetPlacement(name, target.Name())
	return nil
}
