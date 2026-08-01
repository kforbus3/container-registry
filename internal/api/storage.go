package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kforbus3/container-registry/internal/store"
)

// Storage configuration from the web UI.
//
// Where blobs live is the one setting that cannot be applied by writing it
// down: the bytes already stored do not move themselves. So saving a new
// backend does not switch to it. It records a target, and the switch is a
// separate, explicit migration that copies every blob, verifies each one, and
// only then makes the new backend live.
//
// The environment keeps precedence. A REGISTRY_S3_* value set in a unit file is
// what its author expects to be in force, and silently overriding it from a web
// form is a bad surprise during an incident.

// StorageSettingKey is where the persisted backend configuration lives.
const StorageSettingKey = "storage.backend"

// storageRequest is the body of a save or test request.
type storageRequest struct {
	Kind      string `json:"kind"`
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	PathStyle *bool  `json:"path_style"`
}

// backendFor builds a backend from a request, reusing the stored secret when
// the form leaves it blank -- which is what happens when an operator edits a
// bucket name without retyping a credential they cannot see.
func (s *Server) backendFor(ctx context.Context, req storageRequest) (store.Backend, store.S3Config, error) {
	if req.Kind == "filesystem" {
		b, err := store.NewFilesystemBackend(s.Cfg.DataDir + "/blobs")
		return b, store.S3Config{}, err
	}
	if req.Kind != "s3" {
		return nil, store.S3Config{}, fmt.Errorf("unknown storage kind %q", req.Kind)
	}

	secret := req.SecretKey
	if secret == "" {
		if saved, ok := s.savedStorage(ctx); ok {
			key, err := s.configKey()
			if err != nil {
				return nil, store.S3Config{}, err
			}
			if prev, err := saved.S3(key); err == nil {
				secret = prev.SecretKey
			}
		}
	}
	pathStyle := true
	if req.PathStyle != nil {
		pathStyle = *req.PathStyle
	}
	cfg := store.S3Config{
		Endpoint: strings.TrimSpace(req.Endpoint), Region: strings.TrimSpace(req.Region),
		Bucket: strings.TrimSpace(req.Bucket), Prefix: strings.TrimSpace(req.Prefix),
		AccessKey: strings.TrimSpace(req.AccessKey), SecretKey: secret,
		PathStyle: pathStyle,
	}
	b, err := store.NewS3Backend(cfg)
	return b, cfg.Normalise(), err
}

func (s *Server) configKey() ([]byte, error) { return store.ConfigKey(s.Cfg.DataDir) }

// savedStorage reads the persisted backend configuration, if any.
func (s *Server) savedStorage(ctx context.Context) (store.PersistedConfig, bool) {
	return store.ParsePersisted(s.DB.GetSetting(ctx, StorageSettingKey, ""))
}

// envManaged reports whether the environment dictates storage, in which case
// the UI shows the configuration read-only.
func envManaged() bool {
	_, ok := store.S3ConfigFromEnv()
	return ok
}

// handleStorageSave records a target backend after proving it works.
//
// It deliberately does not switch to it: that is what migration is for. The
// only exception is a registry with nothing stored yet, where there is nothing
// to carry over and making the operator run a migration over zero blobs would
// be ceremony.
func (s *Server) handleStorageSave(w http.ResponseWriter, r *http.Request) {
	if envManaged() {
		writeErr(w, http.StatusConflict,
			"storage is configured by the environment (REGISTRY_S3_BUCKET and friends); "+
				"unset those to manage it here")
		return
	}
	if s.Store.Migrating() {
		writeErr(w, http.StatusConflict, "a storage migration is already running")
		return
	}
	var req storageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	backend, cfg, err := s.backendFor(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Never record a backend that has not been shown to work: a saved
	// configuration that fails is a migration that fails halfway.
	if res := probeBackend(r.Context(), backend); !res.OK {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("%s failed the %s check: %s",
				backend.Name(), res.Stage, res.Error),
			"stage": res.Stage,
		})
		return
	}

	persisted := store.PersistedConfig{Kind: "filesystem"}
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
	if err := s.DB.SetSetting(r.Context(), StorageSettingKey, blob); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save the configuration")
		return
	}
	s.audit(r, "storage.configure", "", "", backend.Name())

	// With nothing stored there is nothing to migrate, so apply it now.
	empty := s.storedObjectCount(r.Context()) == 0
	if empty {
		s.Store.SetBackend(backend)
		s.audit(r, "storage.activate", "", "", backend.Name())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"saved":           true,
		"active":          empty,
		"backend":         backend.Name(),
		"needs_migration": !empty,
	})
}

// handleStorageMigrate starts copying blobs into the saved target backend.
func (s *Server) handleStorageMigrate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.Store.MigrationState())
		return
	}
	if envManaged() {
		writeErr(w, http.StatusConflict, "storage is configured by the environment")
		return
	}
	saved, ok := s.savedStorage(r.Context())
	if !ok {
		writeErr(w, http.StatusBadRequest, "no target storage has been configured")
		return
	}
	backend, err := s.backendFromPersisted(saved)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// The migration outlives this request, so it must not inherit its context.
	if err := s.Store.Migrate(context.Background(), backend, func(err error) {
		if err != nil {
			s.Log.Error("storage migration failed", "err", err)
			return
		}
		s.Log.Info("storage migration complete", "backend", backend.Name())
	}); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(r, "storage.migrate", "", "", backend.Name())
	writeJSON(w, http.StatusAccepted, s.Store.MigrationState())
}

// backendFromPersisted rebuilds a backend from saved configuration.
func (s *Server) backendFromPersisted(p store.PersistedConfig) (store.Backend, error) {
	if p.Kind == "filesystem" {
		return store.NewFilesystemBackend(s.Cfg.DataDir + "/blobs")
	}
	key, err := s.configKey()
	if err != nil {
		return nil, err
	}
	cfg, err := p.S3(key)
	if err != nil {
		return nil, err
	}
	return store.NewS3Backend(cfg)
}

// storedObjectCount counts what the live backend holds, which decides whether a
// switch needs a migration at all.
func (s *Server) storedObjectCount(ctx context.Context) int64 {
	var n int64
	s.Store.WalkBlobs(func(digest string, size int64) error {
		n++
		return nil
	})
	return n
}

// probeResult is the outcome of writing, reading back and deleting one object.
type probeResult struct {
	OK      bool
	Stage   string
	Error   string
	Latency time.Duration
}

// probeBackend proves a backend is reachable and writable, which is the
// question behind every "why did my push fail" after a storage change.
func probeBackend(ctx context.Context, b store.Backend) probeResult {
	started := time.Now()
	body := []byte("registry storage check")
	key := "_probe/registry-storage-check"

	if err := b.Put(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		return probeResult{Stage: "write", Error: err.Error()}
	}
	rc, err := b.Get(ctx, key)
	if err != nil {
		return probeResult{Stage: "read", Error: err.Error()}
	}
	got, err := io.ReadAll(io.LimitReader(rc, int64(len(body))+1))
	rc.Close()
	if err != nil {
		return probeResult{Stage: "read", Error: err.Error()}
	}
	if !bytes.Equal(got, body) {
		return probeResult{Stage: "verify",
			Error: "the object read back does not match what was written"}
	}
	if err := b.Delete(ctx, key); err != nil {
		return probeResult{Stage: "delete", Error: err.Error()}
	}
	return probeResult{OK: true, Latency: time.Since(started)}
}
