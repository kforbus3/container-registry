package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kforbus3/container-registry/internal/auth"
	"github.com/kforbus3/container-registry/internal/config"
	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/gc"
	"github.com/kforbus3/container-registry/internal/sbom"
	"github.com/kforbus3/container-registry/internal/store"
	"github.com/kforbus3/container-registry/internal/webhook"
)

// GC is set by main so the admin API can trigger collection.
func (s *Server) SetCollector(c *gc.Collector) { s.collector = c }

// SetSBOMGenerator wires in automatic SBOM generation. A nil generator simply
// disables the feature.
func (s *Server) SetSBOMGenerator(g *sbom.Generator) { s.sbom = g }

// SetWebhooks wires in event delivery. A nil dispatcher disables it, and Emit
// on a nil dispatcher is a no-op, so call sites need no guard.
func (s *Server) SetWebhooks(d *webhook.Dispatcher) { s.hooks = d }

// SetScheduler wires in scheduled maintenance and the retention engine it uses.
func (s *Server) SetScheduler(sc *gc.Scheduler) {
	s.scheduler = sc
	s.retention = sc.Retention
}

// adminRouter serves the management API mounted at /api.
func (s *Server) adminRouter() http.Handler {
	mux := http.NewServeMux()

	// Session endpoints are the only ones reachable without credentials.
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.Handle("GET /auth/me", s.requireAuth(s.handleMe))
	mux.Handle("POST /auth/password", s.requireAuth(s.handleChangeOwnPassword))

	mux.Handle("GET /stats", s.requireAuth(s.handleStats))
	mux.Handle("GET /audit", s.requireAuth(s.handleAuditList))

	mux.Handle("GET /tokens", s.requireAuth(s.handleTokensList))
	mux.Handle("POST /tokens", s.requireAuth(s.handleTokenCreate))
	mux.Handle("POST /tokens/{id}/revoke", s.requireAuth(s.handleTokenRevoke))
	mux.Handle("DELETE /tokens/{id}", s.requireAuth(s.handleTokenDelete))

	mux.Handle("GET /users", s.requireAdmin(s.handleUsersList))
	mux.Handle("POST /users", s.requireAdmin(s.handleUserCreate))
	mux.Handle("PATCH /users/{id}", s.requireAdmin(s.handleUserUpdate))
	mux.Handle("DELETE /users/{id}", s.requireAdmin(s.handleUserDelete))

	mux.Handle("GET /gc", s.requireAdmin(s.handleGCStatus))
	mux.Handle("POST /gc", s.requireAdmin(s.handleGCRun))

	mux.Handle("GET /settings", s.requireAdmin(s.handleSettingsGet))
	mux.Handle("POST /storage/check", s.requireAdmin(s.handleStorageCheck))
	mux.Handle("PUT /storage", s.requireAdmin(s.handleStorageSave))
	mux.Handle("POST /storage/migrate", s.requireAdmin(s.handleStorageMigrate))
	mux.Handle("GET /storage/migrate", s.requireAdmin(s.handleStorageMigrate))

	mux.Handle("GET /webhooks", s.requireAdmin(s.handleWebhookList))
	mux.Handle("POST /webhooks", s.requireAdmin(s.handleWebhookCreate))
	mux.Handle("DELETE /webhooks/{id}", s.requireAdmin(s.handleWebhookDelete))
	mux.Handle("GET /webhooks/{id}/deliveries", s.requireAdmin(s.handleWebhookDeliveries))
	mux.Handle("POST /webhooks/{id}/test", s.requireAdmin(s.handleWebhookTest))

	mux.Handle("GET /maintenance", s.requireAdmin(s.handleMaintenanceHistory))
	mux.Handle("POST /maintenance/sweep", s.requireAdmin(s.handleMaintenanceSweep))
	mux.Handle("POST /retention/preview", s.requireAdmin(s.handleRetentionPreview))

	// Repository paths contain slashes, so this subtree is routed by hand.
	mux.Handle("/repositories", s.requireAuth(s.handleRepoList))
	mux.Handle("/repositories/", s.requireAuth(s.handleRepoSubtree))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "no such API endpoint")
	})
	return mux
}

// ---------------------------------------------------------------- middleware

func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.resolvePrincipal(r)
		if err != nil || p == nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		r = r.WithContext(withPrincipal(r.Context(), p))
		if !s.allowRequest(w, r) {
			return
		}
		next(w, r)
	})
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if p := principalFrom(r.Context()); p == nil || !p.Admin {
			writeErr(w, http.StatusForbidden, "administrator privileges required")
			return
		}
		next(w, r)
	})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- session

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.Auth.AuthenticatePassword(r.Context(), req.Username, req.Password)
	if err != nil {
		s.DB.Audit(r.Context(), req.Username, "login.failed", "", "", err.Error(), remoteIP(r))
		if errors.Is(err, auth.ErrDisabled) {
			writeErr(w, http.StatusForbidden, "account is disabled")
			return
		}
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	sid, err := auth.NewSessionID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	expires := time.Now().Add(s.Cfg.SessionTTL)
	if err := s.DB.CreateSession(r.Context(), sid, p.UserID, expires); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	s.DB.TouchUserLogin(r.Context(), p.UserID)
	s.DB.Audit(r.Context(), p.Username, "login", "", "", "web ui", remoteIP(r))

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.Cfg.TLSEnabled(),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, principalView(p))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		s.DB.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.Cfg.TLSEnabled(), SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

type principalViewJSON struct {
	Username    string `json:"username"`
	Admin       bool   `json:"admin"`
	ViaToken    bool   `json:"via_token"`
	TokenName   string `json:"token_name,omitempty"`
	CanPull     bool   `json:"can_pull"`
	CanPush     bool   `json:"can_push"`
	CanDelete   bool   `json:"can_delete"`
	RepoPattern string `json:"repo_pattern"`
}

func principalView(p *auth.Principal) principalViewJSON {
	return principalViewJSON{
		Username: p.Username, Admin: p.Admin, ViaToken: p.TokenID != 0, TokenName: p.TokenName,
		CanPull: p.CanPull, CanPush: p.CanPush, CanDelete: p.CanDelete, RepoPattern: p.RepoPattern,
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, principalView(principalFrom(r.Context())))
}

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFrom(r.Context())
	if p.TokenID != 0 {
		writeErr(w, http.StatusForbidden, "password changes require an interactive login, not a token")
		return
	}
	u, err := s.DB.GetUser(r.Context(), p.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to load account")
		return
	}
	if !auth.CheckPassword(u.PasswordHash, req.CurrentPassword) {
		writeErr(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.SetUserPassword(r.Context(), u.ID, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to update password")
		return
	}
	s.audit(r, "user.password_changed", "", u.Username, "self-service")
	writeJSON(w, http.StatusOK, map[string]string{"status": "password updated"})
}

// ---------------------------------------------------------------- stats & audit

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.DB.Stats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to compute stats")
		return
	}
	diskBytes, diskBlobs, _ := s.Store.DiskUsage()
	writeJSON(w, http.StatusOK, map[string]any{
		"repositories":     st.Repositories,
		"tags":             st.Tags,
		"manifests":        st.Manifests,
		"blobs":            st.Blobs,
		"users":            st.Users,
		"active_tokens":    st.ActiveTokens,
		"logical_bytes":    st.SizeBytes,
		"disk_bytes":       diskBytes,
		"disk_blob_count":  diskBlobs,
		"anonymous_pull":   s.Cfg.AllowAnonymousPull,
		"tls":              s.Cfg.TLSEnabled(),
		"max_upload_bytes": s.Cfg.MaxUploadBytes,
		"sbom":             s.sbomStats(),
	})
}

// sbomStats reports generator activity, or nil when the feature is disabled.
func (s *Server) sbomStats() any {
	if s.sbom == nil {
		return nil
	}
	st := s.sbom.Stats()
	return map[string]any{
		"enabled":   true,
		"queued":    st.Queued,
		"generated": st.Generated,
		"skipped":   st.Skipped,
		"failed":    st.Failed,
		"dropped":   st.Dropped,
	}
}

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if !p.Admin {
		writeErr(w, http.StatusForbidden, "administrator privileges required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.DB.ListAudit(r.Context(), r.URL.Query().Get("repo"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read audit log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// ---------------------------------------------------------------- tokens

func (s *Server) handleTokensList(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	// Non-admins see only their own tokens.
	owner := p.UserID
	if p.Admin && r.URL.Query().Get("all") == "true" {
		owner = 0
	}
	tokens, err := s.DB.ListTokens(r.Context(), owner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

type tokenCreateRequest struct {
	Name        string `json:"name"`
	CanPull     bool   `json:"can_pull"`
	CanPush     bool   `json:"can_push"`
	CanDelete   bool   `json:"can_delete"`
	IsAdmin     bool   `json:"is_admin"`
	RepoPattern string `json:"repo_pattern"`
	ExpiresDays int    `json:"expires_days"`
	// Username lets an admin mint a token on behalf of another account.
	Username string `json:"username"`
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req tokenCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Name) > 100 {
		writeErr(w, http.StatusBadRequest, "name must be at most 100 characters")
		return
	}
	p := principalFrom(r.Context())
	if p.TokenID != 0 && !p.Admin {
		writeErr(w, http.StatusForbidden, "tokens cannot mint further tokens")
		return
	}

	ownerID := p.UserID
	if req.Username != "" {
		if !p.Admin {
			writeErr(w, http.StatusForbidden, "only administrators can create tokens for another user")
			return
		}
		u, err := s.DB.GetUserByName(r.Context(), req.Username)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no such user")
			return
		}
		ownerID = u.ID
	}
	if req.IsAdmin && !p.Admin {
		writeErr(w, http.StatusForbidden, "only administrators can create admin tokens")
		return
	}
	if !req.CanPull && !req.CanPush && !req.CanDelete && !req.IsAdmin {
		writeErr(w, http.StatusBadRequest, "token must grant at least one permission")
		return
	}
	pattern := strings.TrimSpace(req.RepoPattern)
	if pattern == "" {
		pattern = "*"
	}
	// A non-admin cannot widen scope beyond what they can already reach; today
	// users hold full rights, so this only guards against a malformed pattern.
	if len(pattern) > 500 {
		writeErr(w, http.StatusBadRequest, "repo_pattern is too long")
		return
	}

	plaintext, prefix, hash, err := auth.GenerateToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	t := &db.Token{
		Name: req.Name, UserID: ownerID, Prefix: prefix, SecretHash: hash,
		CanPull: req.CanPull, CanPush: req.CanPush, CanDelete: req.CanDelete,
		IsAdmin: req.IsAdmin, RepoPattern: pattern,
	}
	if req.ExpiresDays > 0 {
		exp := time.Now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour)
		t.ExpiresAt = &exp
	}
	created, err := s.DB.CreateToken(r.Context(), t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to store token")
		return
	}
	s.audit(r, "token.create", "", req.Name, "scope="+pattern)

	// The plaintext is returned exactly once and never stored.
	writeJSON(w, http.StatusCreated, map[string]any{"token": created, "secret": plaintext})
}

// tokenByID loads a token and enforces that the caller may manage it.
func (s *Server) tokenByID(w http.ResponseWriter, r *http.Request) (*db.Token, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid token id")
		return nil, false
	}
	t, err := s.DB.GetToken(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such token")
		return nil, false
	}
	p := principalFrom(r.Context())
	if !p.Admin && t.UserID != p.UserID {
		writeErr(w, http.StatusForbidden, "this token belongs to another user")
		return nil, false
	}
	return t, true
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tokenByID(w, r)
	if !ok {
		return
	}
	if err := s.DB.RevokeToken(r.Context(), t.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}
	s.audit(r, "token.revoke", "", t.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tokenByID(w, r)
	if !ok {
		return
	}
	if err := s.DB.DeleteToken(r.Context(), t.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to delete token")
		return
	}
	s.audit(r, "token.delete", "", t.Name, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------------------------------------------------------------- users

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(strings.ToLower(req.Username))
	if !validUsername(req.Username) {
		writeErr(w, http.StatusBadRequest, "username must be 2-64 characters of letters, digits, '.', '_' or '-'")
		return
	}
	if req.Role != "admin" {
		req.Role = "user"
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.DB.GetUserByName(r.Context(), req.Username); err == nil {
		writeErr(w, http.StatusConflict, "a user with that name already exists")
		return
	}
	u, err := s.DB.CreateUser(r.Context(), req.Username, hash, req.Role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	s.audit(r, "user.create", "", u.Username, "role="+u.Role)
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.DB.GetUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such user")
		return
	}

	// Refuse any change that would leave the registry with no usable admin.
	losingAdmin := (req.Role != nil && *req.Role != "admin" && u.IsAdmin()) ||
		(req.Disabled != nil && *req.Disabled && u.IsAdmin() && !u.Disabled)
	if losingAdmin {
		n, err := s.DB.CountAdmins(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to count administrators")
			return
		}
		if n <= 1 {
			writeErr(w, http.StatusConflict, "cannot remove the last administrator")
			return
		}
	}

	if req.Role != nil {
		role := *req.Role
		if role != "admin" && role != "user" {
			writeErr(w, http.StatusBadRequest, "role must be 'admin' or 'user'")
			return
		}
		if err := s.DB.SetUserRole(r.Context(), id, role); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to update role")
			return
		}
		s.audit(r, "user.role_changed", "", u.Username, role)
	}
	if req.Disabled != nil {
		if err := s.DB.SetUserDisabled(r.Context(), id, *req.Disabled); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to update account state")
			return
		}
		s.audit(r, "user.disabled_changed", "", u.Username, strconv.FormatBool(*req.Disabled))
	}
	if req.Password != nil {
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.DB.SetUserPassword(r.Context(), id, hash); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to update password")
			return
		}
		// Force re-authentication everywhere after an administrative reset.
		s.DB.ExecContext(r.Context(), `DELETE FROM sessions WHERE user_id = ?`, id)
		s.audit(r, "user.password_reset", "", u.Username, "by administrator")
	}

	updated, err := s.DB.GetUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to reload user")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid user id")
		return
	}
	p := principalFrom(r.Context())
	if p.UserID == id {
		writeErr(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	u, err := s.DB.GetUser(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such user")
		return
	}
	if u.IsAdmin() && !u.Disabled {
		n, err := s.DB.CountAdmins(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to count administrators")
			return
		}
		if n <= 1 {
			writeErr(w, http.StatusConflict, "cannot delete the last administrator")
			return
		}
	}
	if err := s.DB.DeleteUser(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	s.audit(r, "user.delete", "", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func validUsername(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- access grants

// repoGrants lists or creates per-repository access grants.
func (s *Server) repoGrants(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	p := principalFrom(r.Context())
	switch r.Method {
	case http.MethodGet:
		grants, err := s.DB.RepoGrants(r.Context(), repo.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list grants")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"grants": grants})

	case http.MethodPost:
		// Granting access is itself an administrative act on the repository.
		if !p.Admin && !s.hasRepoRole(r, repo, db.RoleAdmin) {
			writeErr(w, http.StatusForbidden,
				"administrator access to this repository is required to grant it")
			return
		}
		var req struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !db.ValidRole(req.Role) {
			writeErr(w, http.StatusBadRequest, "role must be read, write or admin")
			return
		}
		u, err := s.DB.GetUserByName(r.Context(), req.Username)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no such user")
			return
		}
		if err := s.DB.GrantRepoAccess(r.Context(), repo.ID, u.ID, req.Role); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to grant access")
			return
		}
		s.audit(r, "grant.create", repo.Name, req.Username, req.Role)
		writeJSON(w, http.StatusCreated, map[string]string{
			"username": req.Username, "role": req.Role,
		})

	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) repoGrantUser(w http.ResponseWriter, r *http.Request, repo *db.Repository, username string) {
	if r.Method != http.MethodDelete {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p := principalFrom(r.Context())
	if !p.Admin && !s.hasRepoRole(r, repo, db.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "administrator access to this repository is required")
		return
	}
	u, err := s.DB.GetUserByName(r.Context(), username)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such user")
		return
	}
	if err := s.DB.RevokeRepoAccess(r.Context(), repo.ID, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to revoke access")
		return
	}
	s.audit(r, "grant.revoke", repo.Name, username, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// hasRepoRole reports whether the caller holds at least the given role on a
// repository through a grant.
func (s *Server) hasRepoRole(r *http.Request, repo *db.Repository, need string) bool {
	p := principalFrom(r.Context())
	role, governed, err := s.DB.RepoAccess(r.Context(), repo.ID, p.UserID)
	if err != nil {
		return false
	}
	if !governed {
		// Ungoverned repositories keep the previous behaviour: anyone who can
		// push to it may also configure it.
		return p.CanPushRepo(repo.Name)
	}
	return db.RoleRank(role) >= db.RoleRank(need)
}

// ---------------------------------------------------------------- webhooks

func (s *Server) handleWebhookList(w http.ResponseWriter, r *http.Request) {
	var repoID int64
	if name := r.URL.Query().Get("repository"); name != "" {
		repo, err := s.DB.GetRepository(r.Context(), name)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no such repository")
			return
		}
		repoID = repo.ID
	}
	hooks, err := s.DB.ListWebhooks(r.Context(), repoID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": hooks, "events": db.AllEvents})
}

func (s *Server) handleWebhookCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		URL        string `json:"url"`
		Secret     string `json:"secret"`
		Events     string `json:"events"`
		Repository string `json:"repository"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name, req.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	if req.Name == "" || req.URL == "" {
		writeErr(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		writeErr(w, http.StatusBadRequest, "url must be http or https")
		return
	}
	if req.Events == "" {
		req.Events = "*"
	}
	hook := &db.Webhook{
		Name: req.Name, URL: req.URL, Secret: req.Secret,
		Events: req.Events, Enabled: true,
	}
	if req.Repository != "" {
		repo, err := s.DB.GetRepository(r.Context(), req.Repository)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no such repository")
			return
		}
		hook.RepoID = &repo.ID
	}
	created, err := s.DB.CreateWebhook(r.Context(), hook)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create webhook")
		return
	}
	s.audit(r, "webhook.create", req.Repository, req.Name, req.URL)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleWebhookDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	if err := s.DB.DeleteWebhook(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to delete webhook")
		return
	}
	s.audit(r, "webhook.delete", "", r.PathValue("id"), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	deliveries, err := s.DB.Deliveries(r.Context(), id, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read deliveries")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": deliveries})
}

// handleWebhookTest sends a synthetic event, so an endpoint can be verified
// without waiting for a real push.
func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	if s.hooks == nil {
		writeErr(w, http.StatusServiceUnavailable, "webhooks are disabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	hook, err := s.DB.GetWebhook(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such webhook")
		return
	}
	var repoID int64
	if hook.RepoID != nil {
		repoID = *hook.RepoID
	}
	s.hooks.Emit(webhook.Event{
		Event: db.EventPushTag, RepoID: repoID,
		Repository: "test", Reference: "test",
		Actor: principalFrom(r.Context()).Display(),
		Data:  map[string]any{"test": true},
	})
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "test event queued"})
}

// ---------------------------------------------------------------- retention

// mustRetentionRules returns a repository's rules, or an empty list if they
// cannot be read: the repository page should still render.
func mustRetentionRules(r *http.Request, s *Server, repoID int64) []*db.RetentionRule {
	rules, err := s.DB.RetentionRules(r.Context(), repoID)
	if err != nil {
		return []*db.RetentionRule{}
	}
	return rules
}

// mustRepoGrants returns a repository's access grants, or an empty list if they
// cannot be read: the repository page should still render.
func mustRepoGrants(r *http.Request, s *Server, repoID int64) []*db.RepoGrant {
	grants, err := s.DB.RepoGrants(r.Context(), repoID)
	if err != nil {
		return []*db.RepoGrant{}
	}
	return grants
}

// repoRetention lists or creates retention rules for a repository.
func (s *Server) repoRetention(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	p := principalFrom(r.Context())
	switch r.Method {
	case http.MethodGet:
		rules, err := s.DB.RetentionRules(r.Context(), repo.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list retention rules")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": rules})

	case http.MethodPost:
		if !p.CanDeleteRepo(repo.Name) {
			writeErr(w, http.StatusForbidden,
				"delete permission is required to configure retention")
			return
		}
		var req struct {
			Kind      string `json:"kind"`
			Pattern   string `json:"pattern"`
			KeepCount int    `json:"keep_count"`
			MaxAge    string `json:"max_age"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Pattern == "" {
			req.Pattern = "*"
		}
		switch req.Kind {
		case db.RetentionKeepLast:
			if req.KeepCount <= 0 {
				writeErr(w, http.StatusBadRequest, "keep_count must be greater than zero")
				return
			}
		case db.RetentionMaxAge:
			d, err := time.ParseDuration(req.MaxAge)
			if err != nil || d <= 0 {
				writeErr(w, http.StatusBadRequest,
					`max_age must be a positive duration such as "720h"`)
				return
			}
		case db.RetentionProtect:
		default:
			writeErr(w, http.StatusBadRequest,
				"kind must be keep_last, delete_older_than or protect")
			return
		}
		rule, err := s.DB.CreateRetentionRule(r.Context(), &db.RetentionRule{
			RepoID: repo.ID, Kind: req.Kind, Pattern: req.Pattern,
			KeepCount: req.KeepCount, MaxAge: req.MaxAge, Enabled: true,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to create rule")
			return
		}
		s.audit(r, "retention.create", repo.Name, req.Kind, req.Pattern)
		writeJSON(w, http.StatusCreated, rule)

	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) repoRetentionRule(w http.ResponseWriter, r *http.Request, repo *db.Repository, idStr string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	if !principalFrom(r.Context()).CanDeleteRepo(repo.Name) {
		writeErr(w, http.StatusForbidden, "delete permission is required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.DB.DeleteRetentionRule(r.Context(), repo.ID, id); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to delete rule")
			return
		}
		s.audit(r, "retention.delete", repo.Name, idStr, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case http.MethodPatch:
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Enabled == nil {
			writeErr(w, http.StatusBadRequest, "enabled is required")
			return
		}
		if err := s.DB.SetRetentionRuleEnabled(r.Context(), repo.ID, id, *req.Enabled); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to update rule")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRetentionPreview shows what a sweep would delete without deleting it.
// Retention removes things permanently, so it must be possible to read the
// decision before trusting it.
func (s *Server) handleRetentionPreview(w http.ResponseWriter, r *http.Request) {
	if s.retention == nil {
		writeErr(w, http.StatusServiceUnavailable, "retention is not configured")
		return
	}
	res, err := s.retention.ApplyAll(r.Context(), true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "preview failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleMaintenanceHistory(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := s.DB.MaintenanceRuns(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read history")
		return
	}
	interval := ""
	if s.scheduler != nil {
		interval = s.scheduler.Interval.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"runs":     runs,
		"interval": interval,
	})
}

// handleMaintenanceSweep runs retention and collection immediately.
func (s *Server) handleMaintenanceSweep(w http.ResponseWriter, r *http.Request) {
	if s.scheduler == nil {
		writeErr(w, http.StatusServiceUnavailable, "scheduled maintenance is not configured")
		return
	}
	s.scheduler.Sweep(r.Context(), "manual")
	s.audit(r, "maintenance.sweep", "", "", "manual")
	writeJSON(w, http.StatusOK, map[string]string{"status": "swept"})
}

// ---------------------------------------------------------------- gc & settings

func (s *Server) handleGCStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"running": s.collector.Running(),
		"last":    s.collector.Last(),
	})
}

func (s *Server) handleGCRun(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"
	res, err := s.collector.Run(r.Context(), dryRun)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(r, "gc.run", "", "", fmt.Sprintf("dry_run=%v deleted=%d reclaimed=%d",
		dryRun, res.BlobsDeleted, res.BytesReclaimed))
	writeJSON(w, http.StatusOK, res)
}

// writeRateLimit reports the limit actually applied to writes, which falls back
// to the general limit when no separate one is configured.
func writeRateLimit(cfg *config.Config) int {
	if cfg.RateLimitWrites > 0 {
		return cfg.RateLimitWrites
	}
	return cfg.RateLimit
}

// storageView describes where blobs live, in terms an operator can check
// against what they configured.
func (s *Server) storageView() map[string]any {
	out := map[string]any{
		"backend":         s.Store.Backend(),
		"scratch_dir":     s.Store.Root(),
		"is_object_store": false,
		"env_managed":     envManaged(),
		"editable":        !envManaged(),
		"migration":       s.Store.MigrationState(),
	}
	if raw, ok := store.S3ConfigFromEnv(); ok {
		// Report the effective configuration, not the raw environment: an
		// unset region is us-east-1 in practice, and showing it blank would
		// misdescribe what the registry is actually doing.
		describeS3(out, raw.Normalise())
		out["source"] = "environment"
		return out
	}

	out["source"] = "database"
	saved, ok := s.savedStorage(context.Background())
	if !ok {
		out["kind"] = "filesystem"
		return out
	}
	if saved.Kind != "s3" {
		out["kind"] = "filesystem"
		return out
	}
	describeS3(out, store.S3Config{
		Endpoint: saved.Endpoint, Region: saved.Region, Bucket: saved.Bucket,
		Prefix: saved.Prefix, AccessKey: saved.AccessKey, PathStyle: saved.PathStyle,
	}.Normalise())
	// The saved configuration is the target; whether it is live depends on
	// whether a migration has carried the blobs across yet.
	out["active"] = strings.HasPrefix(s.Store.Backend(), "s3(")
	return out
}

// describeS3 fills in the fields an operator can check against what they typed.
// The secret is never included; the access key is masked to identify which
// credential is in use without disclosing it.
func describeS3(out map[string]any, cfg store.S3Config) {
	out["is_object_store"] = true
	out["kind"] = "s3"
	out["endpoint"] = cfg.Endpoint
	out["bucket"] = cfg.Bucket
	out["region"] = cfg.Region
	out["prefix"] = cfg.Prefix
	out["path_style"] = cfg.PathStyle
	out["access_key"] = maskKey(cfg.AccessKey)
}

// maskKey shows enough of an access key to identify it without disclosing it.
func maskKey(k string) string {
	if k == "" {
		return ""
	}
	if len(k) <= 4 {
		return strings.Repeat("*", len(k))
	}
	return k[:4] + strings.Repeat("*", len(k)-4)
}

// handleStorageCheck verifies the blob store is actually reachable and
// writable, which is the question an operator has after configuring one:
// credentials and bucket policies fail at the first push otherwise.
func (s *Server) handleStorageCheck(w http.ResponseWriter, r *http.Request) {
	probe := []byte("registry storage check")
	started := time.Now()

	digest, err := s.Store.PutBytes(probe)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "stage": "write", "error": err.Error(),
			"backend": s.Store.Backend(),
		})
		return
	}
	got, err := s.Store.ReadAll(digest)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "stage": "read", "error": err.Error(),
			"backend": s.Store.Backend(),
		})
		return
	}
	if !bytes.Equal(got, probe) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "stage": "verify",
			"error":   "the object read back does not match what was written",
			"backend": s.Store.Backend(),
		})
		return
	}
	// The probe is content-addressed like anything else, so leaving it would be
	// harmless, but removing it also exercises delete.
	deleteErr := ""
	if err := s.Store.Delete(digest); err != nil {
		deleteErr = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"backend":      s.Store.Backend(),
		"latency_ms":   time.Since(started).Milliseconds(),
		"delete_error": deleteErr,
	})
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"addr":                 s.Cfg.Addr,
		"data_dir":             s.Cfg.DataDir,
		"realm":                s.Cfg.Realm,
		"tls":                  s.Cfg.TLSEnabled(),
		"anonymous_pull":       s.Cfg.AllowAnonymousPull,
		"max_upload_bytes":     s.Cfg.MaxUploadBytes,
		"session_ttl":          s.Cfg.SessionTTL.String(),
		"storage":              s.storageView(),
		"gc_grace":             s.collector.Grace.String(),
		"gc_upload_ttl":        s.collector.UploadTTL.String(),
		"maintenance_interval": s.Cfg.MaintenanceInterval.String(),
		"sbom_enabled":         s.Cfg.SBOMEnabled,
		"webhooks_enabled":     s.Cfg.WebhooksEnabled,
		"rate_limit":           s.Cfg.RateLimit,
		"rate_limit_writes":    writeRateLimit(s.Cfg),
		"rate_burst":           s.Cfg.RateBurst,
		"token_auth":           s.Cfg.TokenAuth,
		"token_realm":          s.Cfg.TokenRealm,
		"proxy_remote":         s.Cfg.ProxyRemote,
		"proxy_prefix":         s.Cfg.ProxyPrefix,
		"metrics_protected":    s.Cfg.MetricsToken != "",
	})
}

// ---------------------------------------------------------------- repositories

func (s *Server) handleRepoList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p := principalFrom(r.Context())
	repos, err := s.DB.ListRepositories(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}
	visible := make([]*db.Repository, 0, len(repos))
	for _, repo := range repos {
		if p.CanPullRepo(repo.Name) || repo.Public {
			visible = append(visible, repo)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": visible})
}

// handleRepoSubtree routes /repositories/<name>[/tags[/<tag>]|/manifests/<digest>],
// where <name> may itself contain slashes.
func (s *Server) handleRepoSubtree(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/repositories/")
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		writeErr(w, http.StatusBadRequest, "repository name is required")
		return
	}
	segments := strings.Split(rest, "/")

	// Repository names contain slashes, so the path is split on the last
	// routing verb. Every sub-resource must be listed here: one that is missing
	// gets swallowed into the repository name and reported as "no such
	// repository", which is a confusing way to say "unrouted".
	verbIdx := -1
	for i := len(segments) - 1; i > 0; i-- {
		switch segments[i] {
		case "tags", "manifests", "retention", "grants":
			verbIdx = i
		}
		if verbIdx >= 0 {
			break
		}
	}
	name := rest
	var tail []string
	if verbIdx > 0 {
		name = strings.Join(segments[:verbIdx], "/")
		tail = segments[verbIdx:]
	}

	unescaped, err := unescapePath(name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid repository name")
		return
	}
	name = unescaped
	if !validRepoName(name) {
		writeErr(w, http.StatusBadRequest, "invalid repository name")
		return
	}

	repo, err := s.DB.GetRepository(r.Context(), name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such repository")
		return
	}
	p := principalFrom(r.Context())
	if !p.CanPullRepo(name) && !repo.Public {
		writeErr(w, http.StatusForbidden, "you do not have access to this repository")
		return
	}

	switch {
	case len(tail) == 0:
		s.repoRoot(w, r, repo)
	case len(tail) == 1 && tail[0] == "tags":
		s.repoTags(w, r, repo)
	case len(tail) == 1 && tail[0] == "grants":
		s.repoGrants(w, r, repo)
	case len(tail) == 2 && tail[0] == "grants":
		s.repoGrantUser(w, r, repo, tail[1])
	case len(tail) == 1 && tail[0] == "retention":
		s.repoRetention(w, r, repo)
	case len(tail) == 2 && tail[0] == "retention":
		s.repoRetentionRule(w, r, repo, tail[1])
	case len(tail) == 2 && tail[0] == "tags":
		s.repoTag(w, r, repo, tail[1])
	case len(tail) == 3 && tail[0] == "manifests" && tail[2] == "sbom":
		s.repoSBOM(w, r, repo, tail[1])
	case len(tail) == 2 && tail[0] == "manifests":
		s.repoManifest(w, r, repo, tail[1])
	default:
		writeErr(w, http.StatusNotFound, "no such API endpoint")
	}
}

func unescapePath(s string) (string, error) {
	// Path segments arrive already decoded by net/http for the most part, but
	// a name pushed with %2F needs one more pass.
	if !strings.Contains(s, "%") {
		return s, nil
	}
	out, err := urlPathUnescape(s)
	if err != nil {
		return "", err
	}
	return out, nil
}

func (s *Server) repoRoot(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	p := principalFrom(r.Context())
	switch r.Method {
	case http.MethodGet:
		tags, err := s.DB.ListTagsDetailed(r.Context(), repo.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list tags")
			return
		}
		manifests, err := s.DB.ListManifests(r.Context(), repo.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list manifests")
			return
		}
		tagged := map[string]bool{}
		for _, t := range tags {
			tagged[t.Digest] = true
		}
		// A manifest with a subject is a referrer — an SBOM, signature or
		// attestation. It carries no tag by design and is reachable through the
		// manifest it describes, so it is not garbage. Only genuinely
		// unreferenced manifests belong in the reclaimable list.
		untagged := []*db.Manifest{}
		referrers := []*db.Manifest{}
		for _, m := range manifests {
			switch {
			case m.Subject != "":
				referrers = append(referrers, m)
			case !tagged[m.Digest]:
				untagged = append(untagged, m)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"repository":         repo,
			"tags":               tags,
			"manifests":          manifests,
			"untagged_manifests": untagged,
			"referrer_manifests": referrers,
		})

	case http.MethodPatch:
		if !p.Admin && !p.CanPushRepo(repo.Name) {
			writeErr(w, http.StatusForbidden, "push permission is required to configure a repository")
			return
		}
		var req struct {
			Public      *bool   `json:"public"`
			Immutable   *bool   `json:"immutable"`
			Description *string `json:"description"`
			QuotaBytes  *int64  `json:"quota_bytes"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		public, immutable, desc := repo.Public, repo.Immutable, repo.Description
		if req.Public != nil {
			public = *req.Public
		}
		if req.Immutable != nil {
			immutable = *req.Immutable
		}
		if req.Description != nil {
			desc = *req.Description
			if len(desc) > 1000 {
				writeErr(w, http.StatusBadRequest, "description must be at most 1000 characters")
				return
			}
		}
		if err := s.DB.UpdateRepository(r.Context(), repo.ID, public, immutable, desc); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to update repository")
			return
		}
		if req.QuotaBytes != nil {
			if *req.QuotaBytes < 0 {
				writeErr(w, http.StatusBadRequest, "quota_bytes cannot be negative")
				return
			}
			if !principalFrom(r.Context()).Admin {
				writeErr(w, http.StatusForbidden, "only administrators can set a quota")
				return
			}
			if err := s.DB.SetRepositoryQuota(r.Context(), repo.ID, *req.QuotaBytes); err != nil {
				writeErr(w, http.StatusInternalServerError, "failed to set quota")
				return
			}
			s.audit(r, "repo.quota", repo.Name, "", strconv.FormatInt(*req.QuotaBytes, 10))
		}
		s.audit(r, "repo.update", repo.Name, "",
			fmt.Sprintf("public=%v immutable=%v", public, immutable))
		updated, _ := s.DB.GetRepository(r.Context(), repo.Name)
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if !p.CanDeleteRepo(repo.Name) {
			writeErr(w, http.StatusForbidden, "delete permission is required")
			return
		}
		if err := s.DB.DeleteRepository(r.Context(), repo.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to delete repository")
			return
		}
		s.audit(r, "repo.delete", repo.Name, "", "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) repoTags(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	switch r.Method {
	case http.MethodGet:
		// Paged, because a repository with thousands of tags should not have to
		// be rendered in full to look at the first few.
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		page, err := s.DB.ListTagsPage(r.Context(), repo.ID,
			r.URL.Query().Get("search"), limit, offset)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list tags")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tags": page.Tags, "total": page.Total,
			"limit": limit, "offset": offset,
		})

	case http.MethodPost:
		s.createTag(w, r, repo)

	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// createTag points a new tag at an existing manifest, identified either by
// digest or by an existing tag. This is the API-driven retag operation.
func (s *Server) createTag(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	p := principalFrom(r.Context())
	if !p.CanPushRepo(repo.Name) {
		writeErr(w, http.StatusForbidden, "push permission is required to create a tag")
		return
	}
	var req struct {
		Tag string `json:"tag"`
		// Target is a manifest digest or an existing tag in this repository.
		Target string `json:"target"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Tag, req.Target = strings.TrimSpace(req.Tag), strings.TrimSpace(req.Target)
	if !validTag(req.Tag) {
		writeErr(w, http.StatusBadRequest, "invalid tag name")
		return
	}
	if req.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required (a manifest digest or an existing tag)")
		return
	}

	digest := req.Target
	if !store.ValidDigest(digest) {
		t, err := s.DB.GetTag(r.Context(), repo.ID, req.Target)
		if err != nil {
			writeErr(w, http.StatusNotFound, "target tag does not exist in this repository")
			return
		}
		digest = t.Digest
	}
	if _, err := s.DB.GetManifest(r.Context(), repo.ID, digest); err != nil {
		writeErr(w, http.StatusNotFound, "target manifest does not exist in this repository")
		return
	}
	if repo.Immutable {
		if existing, err := s.DB.GetTag(r.Context(), repo.ID, req.Tag); err == nil && existing.Digest != digest {
			writeErr(w, http.StatusConflict, "repository is immutable and this tag already exists")
			return
		}
	}
	if err := s.DB.PutTag(r.Context(), repo.ID, req.Tag, digest); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create tag")
		return
	}
	s.audit(r, "tag.create", repo.Name, req.Tag, digest)
	s.emit(r, repo.ID, db.EventPushTag, repo.Name, req.Tag, digest)
	writeJSON(w, http.StatusCreated, map[string]string{"tag": req.Tag, "digest": digest})
}

func (s *Server) repoTag(w http.ResponseWriter, r *http.Request, repo *db.Repository, tag string) {
	p := principalFrom(r.Context())
	switch r.Method {
	case http.MethodGet:
		t, err := s.DB.GetTag(r.Context(), repo.ID, tag)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no such tag")
			return
		}
		writeJSON(w, http.StatusOK, t)

	case http.MethodDelete:
		if !p.CanDeleteRepo(repo.Name) {
			writeErr(w, http.StatusForbidden, "delete permission is required")
			return
		}
		if _, err := s.DB.GetTag(r.Context(), repo.ID, tag); err != nil {
			writeErr(w, http.StatusNotFound, "no such tag")
			return
		}
		if err := s.DB.DeleteTag(r.Context(), repo.ID, tag); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to delete tag")
			return
		}
		s.audit(r, "tag.delete", repo.Name, tag, "")
		s.emit(r, repo.ID, db.EventDeleteTag, repo.Name, tag, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// repoManifest returns a manifest with its parsed content and, for image
// manifests, the decoded image config.
func (s *Server) repoManifest(w http.ResponseWriter, r *http.Request, repo *db.Repository, digest string) {
	p := principalFrom(r.Context())
	if !store.ValidDigest(digest) {
		writeErr(w, http.StatusBadRequest, "invalid digest")
		return
	}
	m, err := s.DB.GetManifest(r.Context(), repo.ID, digest)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such manifest")
		return
	}

	if r.Method == http.MethodDelete {
		if !p.CanDeleteRepo(repo.Name) {
			writeErr(w, http.StatusForbidden, "delete permission is required")
			return
		}
		if err := s.DB.DeleteManifest(r.Context(), repo.ID, digest); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to delete manifest")
			return
		}
		s.audit(r, "manifest.delete", repo.Name, digest, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	refs, err := s.DB.ManifestRefs(r.Context(), m.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to load manifest references")
		return
	}
	tags, _ := s.DB.TagsForDigest(r.Context(), repo.ID, digest)

	resp := map[string]any{"manifest": m, "refs": refs, "tags": tags}
	if body, err := s.Store.ReadAll(digest); err == nil {
		var raw any
		if json.Unmarshal(body, &raw) == nil {
			resp["content"] = raw
		}
	}
	// Decode the image config so the UI can show entrypoint, env and history.
	if m.ConfigDigest != "" {
		if cfgBody, err := s.Store.ReadAll(m.ConfigDigest); err == nil && len(cfgBody) < (2<<20) {
			var cfg imageConfig
			if json.Unmarshal(cfgBody, &cfg) == nil {
				resp["config"] = cfg
			}
		}
	}
	var totalSize int64
	for _, ref := range refs {
		totalSize += ref.Size
	}
	resp["total_size"] = totalSize

	// Surface an automatically generated SBOM, if one has been published for
	// this manifest, so the UI can link to it without a second round trip.
	// Resolving through an index matters here: a tag normally points at one,
	// and the UI would otherwise show "no SBOM" on the page users actually open.
	if found, err := s.findSBOMs(r.Context(), repo, digest); err == nil && len(found) > 0 {
		summary := map[string]any{
			"digest":    found[0].ArtifactDigest,
			"platforms": len(found),
		}
		if found[0].Platform != "" {
			summary["platform"] = found[0].Platform
		}
		if body, err := s.Store.ReadAll(found[0].ArtifactDigest); err == nil {
			var art struct {
				Annotations map[string]string `json:"annotations"`
			}
			if json.Unmarshal(body, &art) == nil {
				if n, ok := art.Annotations["registry.sbom.componentCount"]; ok {
					summary["component_count"] = n
				}
				if ts, ok := art.Annotations["org.opencontainers.image.created"]; ok {
					summary["created"] = ts
				}
			}
		}
		resp["sbom"] = summary
	}
	writeJSON(w, http.StatusOK, resp)
}

// sbomRef locates one generated SBOM: the artifact holding it, the manifest it
// describes, and that manifest's platform when it came from an index.
type sbomRef struct {
	ArtifactDigest string
	SubjectDigest  string
	Platform       string
}

// findSBOMs resolves the SBOMs reachable from a manifest.
//
// An SBOM is attached to the image manifest it describes. A tag, however,
// usually points at an *index* — that is what `docker push` produces even for a
// single platform — and an index gets no SBOM of its own. Looking only at the
// digest the user has in hand would therefore report nothing for the most
// common case, so an index is resolved to the platform manifests beneath it.
func (s *Server) findSBOMs(ctx context.Context, repo *db.Repository, digest string) ([]sbomRef, error) {
	direct, err := s.DB.Referrers(ctx, repo.ID, digest, sbom.MediaType)
	if err != nil {
		return nil, err
	}
	if len(direct) > 0 {
		return []sbomRef{{ArtifactDigest: direct[0].Digest, SubjectDigest: digest}}, nil
	}

	m, err := s.DB.GetManifest(ctx, repo.ID, digest)
	if err != nil || !isIndexType(m.MediaType) {
		return nil, nil
	}
	body, err := s.Store.ReadAll(digest)
	if err != nil {
		return nil, nil
	}
	var idx struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform *struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, nil
	}

	var out []sbomRef
	for _, child := range idx.Manifests {
		platform := ""
		if p := child.Platform; p != nil {
			// Attestation manifests ride in the index as unknown/unknown and
			// never carry an SBOM, so they drop out naturally below.
			platform = p.OS + "/" + p.Architecture
			if p.Variant != "" {
				platform += "/" + p.Variant
			}
		}
		refs, err := s.DB.Referrers(ctx, repo.ID, child.Digest, sbom.MediaType)
		if err != nil {
			return nil, err
		}
		if len(refs) == 0 {
			continue
		}
		out = append(out, sbomRef{
			ArtifactDigest: refs[0].Digest,
			SubjectDigest:  child.Digest,
			Platform:       platform,
		})
	}
	return out, nil
}

// repoSBOM serves the CycloneDX document generated for a manifest. The SBOM is
// also reachable through the standard referrers API; this endpoint just saves
// callers the two extra round trips.
func (s *Server) repoSBOM(w http.ResponseWriter, r *http.Request, repo *db.Repository, digest string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !store.ValidDigest(digest) {
		writeErr(w, http.StatusBadRequest, "invalid digest")
		return
	}
	found, err := s.findSBOMs(r.Context(), repo, digest)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to look up SBOM")
		return
	}
	if len(found) == 0 {
		writeErr(w, http.StatusNotFound,
			"no SBOM has been generated for this manifest yet")
		return
	}
	// A multi-platform index has one SBOM per platform, so the caller has to
	// say which. A single-platform push — what `docker push` produces by
	// default — has exactly one, and needs no qualifier.
	if want := r.URL.Query().Get("platform"); want != "" {
		filtered := found[:0]
		for _, c := range found {
			if c.Platform == want {
				filtered = append(filtered, c)
			}
		}
		found = filtered
		if len(found) == 0 {
			writeErr(w, http.StatusNotFound,
				fmt.Sprintf("no SBOM for platform %q on this manifest", want))
			return
		}
	}
	if len(found) > 1 {
		platforms := make([]string, 0, len(found))
		for _, c := range found {
			platforms = append(platforms, c.Platform)
		}
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"this is a multi-platform index with %d SBOMs; add ?platform= to choose one of: %s",
			len(found), strings.Join(platforms, ", ")))
		return
	}

	if found[0].Platform != "" {
		// Tell the caller which platform they actually got.
		w.Header().Set("X-Registry-Sbom-Platform", found[0].Platform)
	}
	// The artifact manifest carries the document as its single layer.
	artBody, err := s.Store.ReadAll(found[0].ArtifactDigest)
	if err != nil {
		writeErr(w, http.StatusNotFound, "SBOM artifact is missing from storage")
		return
	}
	var art struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(artBody, &art); err != nil || len(art.Layers) == 0 {
		writeErr(w, http.StatusInternalServerError, "malformed SBOM artifact")
		return
	}
	doc, err := s.Store.ReadAll(art.Layers[0].Digest)
	if err != nil {
		writeErr(w, http.StatusNotFound, "SBOM document is missing from storage")
		return
	}
	w.Header().Set("Content-Type", sbom.MediaType)
	w.Header().Set("Content-Disposition", `attachment; filename="sbom.cdx.json"`)
	w.WriteHeader(http.StatusOK)
	w.Write(doc)
}
