package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
	return map[string]any{
		"rules":     rules,
		"backends":  names,
		"default":   s.Store.Router().Fallback().Name(),
		"misplaced": s.misplaced(ctx),
	}
}
