package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/kforbus3/container-registry/internal/auth"
	"github.com/kforbus3/container-registry/internal/config"
	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/gc"
	"github.com/kforbus3/container-registry/internal/ratelimit"
	"github.com/kforbus3/container-registry/internal/sbom"
	"github.com/kforbus3/container-registry/internal/store"
	"github.com/kforbus3/container-registry/internal/vuln"
)

// Server wires together storage, metadata and authentication behind the HTTP
// surface: the OCI /v2 API, the admin API and the web UI.
type Server struct {
	Cfg   *config.Config
	DB    *db.DB
	Store *store.Store
	Auth  *auth.Authenticator
	Log   *slog.Logger

	collector *gc.Collector
	sbom      *sbom.Generator
	vuln      *vuln.Scanner
	scheduler *gc.Scheduler
	retention *gc.Retention

	reads  *ratelimit.Limiter
	writes *ratelimit.Limiter
}

// SetRateLimits installs per-caller limits. Writes are limited separately
// because a push costs far more than a manifest read, so one sensible number
// for both does not exist.
func (s *Server) SetRateLimits(reads, writes ratelimit.Limit) {
	s.reads = ratelimit.New(reads)
	s.writes = ratelimit.New(writes)
}

// rateKey identifies the caller a limit applies to. An authenticated principal
// is limited as itself wherever it connects from; an anonymous caller is
// limited by address, which is the only thing there is to go on.
func (s *Server) rateKey(r *http.Request) string {
	if p := principalFrom(r.Context()); p != nil && !p.IsAnonymous() {
		if p.TokenID != 0 {
			return fmt.Sprintf("token:%d", p.TokenID)
		}
		return fmt.Sprintf("user:%d", p.UserID)
	}
	return "ip:" + remoteIP(r)
}

// allowRequest applies the limit for this request, writing the response itself
// when the caller is over it.
func (s *Server) allowRequest(w http.ResponseWriter, r *http.Request) bool {
	limiter := s.reads
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		limiter = s.writes
	}
	if limiter == nil {
		return true
	}
	ok, retry := limiter.Allow(s.rateKey(r))
	if ok {
		return true
	}
	seconds := int(retry.Seconds() + 0.999)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	s.ociErr(w, http.StatusTooManyRequests, codeTooManyRequests,
		"rate limit exceeded; retry after "+strconv.Itoa(seconds)+"s", nil)
	return false
}

// urlPathUnescape is a thin alias so admin.go does not import net/url directly.
func urlPathUnescape(s string) (string, error) { return url.PathUnescape(s) }

func NewServer(cfg *config.Config, database *db.DB, st *store.Store, log *slog.Logger) *Server {
	return &Server{Cfg: cfg, DB: database, Store: st, Auth: auth.New(database), Log: log}
}

const sessionCookie = "registry_session"

// ---------------------------------------------------------------- OCI errors

// ociError follows the error format in the OCI distribution specification.
type ociError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

type ociErrorBody struct {
	Errors []ociError `json:"errors"`
}

// Error codes defined by the specification.
const (
	codeBlobUnknown         = "BLOB_UNKNOWN"
	codeBlobUploadInvalid   = "BLOB_UPLOAD_INVALID"
	codeBlobUploadUnknown   = "BLOB_UPLOAD_UNKNOWN"
	codeDigestInvalid       = "DIGEST_INVALID"
	codeManifestBlobUnknown = "MANIFEST_BLOB_UNKNOWN"
	codeManifestInvalid     = "MANIFEST_INVALID"
	codeManifestUnknown     = "MANIFEST_UNKNOWN"
	codeNameInvalid         = "NAME_INVALID"
	codeNameUnknown         = "NAME_UNKNOWN"
	codeSizeInvalid         = "SIZE_INVALID"
	codeUnauthorized        = "UNAUTHORIZED"
	codeDenied              = "DENIED"
	codeUnsupported         = "UNSUPPORTED"
	codeTooManyRequests     = "TOOMANYREQUESTS"
)

func (s *Server) ociErr(w http.ResponseWriter, status int, code, message string, detail any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ociErrorBody{Errors: []ociError{{Code: code, Message: message, Detail: detail}}})
}

// challenge sends a 401 with a Basic auth challenge, which is what makes
// `docker login` prompt for and then send credentials.
func (s *Server) challenge(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+s.Cfg.Realm+`"`)
	s.ociErr(w, http.StatusUnauthorized, codeUnauthorized, message, nil)
}

// ---------------------------------------------------------------- JSON helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

type apiError struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

// ---------------------------------------------------------------- names

// repoNameRe implements the repository name grammar from the distribution
// specification: lowercase alphanumeric path components separated by '/', with
// '.', '_', '__' and '-' as internal separators.
var repoNameRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)

// tagRe is the tag grammar: up to 128 characters of word chars, '.' and '-',
// not starting with '.' or '-'.
var tagRe = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

func validRepoName(name string) bool {
	return len(name) > 0 && len(name) <= 255 && repoNameRe.MatchString(name)
}

func validTag(tag string) bool { return tagRe.MatchString(tag) }

// ---------------------------------------------------------------- principals

type ctxKey int

const principalKey ctxKey = iota

func principalFrom(ctx context.Context) *auth.Principal {
	p, _ := ctx.Value(principalKey).(*auth.Principal)
	return p
}

func withPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// resolvePrincipal authenticates a request from an Authorization header or a
// session cookie. It returns nil when no usable credential is present.
func (s *Server) resolvePrincipal(r *http.Request) (*auth.Principal, error) {
	if hdr := r.Header.Get("Authorization"); hdr != "" {
		scheme, value, found := strings.Cut(hdr, " ")
		if !found {
			return nil, auth.ErrBadCredentials
		}
		switch strings.ToLower(scheme) {
		case "basic":
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
			if err != nil {
				return nil, auth.ErrBadCredentials
			}
			user, pass, ok := strings.Cut(string(raw), ":")
			if !ok {
				return nil, auth.ErrBadCredentials
			}
			return s.Auth.AuthenticateCredential(r.Context(), user, pass)
		case "bearer":
			return s.Auth.AuthenticateToken(r.Context(), strings.TrimSpace(value))
		default:
			return nil, auth.ErrBadCredentials
		}
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		return s.Auth.AuthenticateSession(r.Context(), c.Value)
	}
	return nil, nil
}

// remoteIP extracts the client address, honouring X-Forwarded-For when the
// registry sits behind a reverse proxy.
func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, found := strings.Cut(xff, ","); found {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) audit(r *http.Request, action, repo, reference, detail string) {
	p := principalFrom(r.Context())
	s.DB.Audit(context.WithoutCancel(r.Context()), p.Display(), action, repo, reference, detail, remoteIP(r))
}

// ---------------------------------------------------------------- routing

// Handler builds the top-level HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// OCI distribution API. The repository name may contain slashes, so the
	// whole subtree is routed manually in serveV2.
	mux.HandleFunc("/v2/", s.serveV2)
	mux.HandleFunc("/v2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v2/", http.StatusMovedPermanently)
	})

	// Management API and web UI.
	mux.Handle("/api/", http.StripPrefix("/api", s.adminRouter()))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.DB.PingContext(r.Context()); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("/", s.uiHandler())

	return s.withCommonHeaders(s.withRecovery(s.withLogging(mux)))
}

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if strings.HasPrefix(r.URL.Path, "/v2") {
			// A legacy Docker header the OCI specification calls optional and
			// tells clients not to depend on. It is emitted on the registry API
			// only, because some older tooling probes for it.
			w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		} else {
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "same-origin")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic serving request", "path", r.URL.Path, "method", r.Method, "panic", rec)
				s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "internal server error", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wrote {
		sr.status, sr.wrote = code, true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.wrote {
		sr.status, sr.wrote = http.StatusOK, true
	}
	return sr.ResponseWriter.Write(b)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		// Static UI assets would drown out anything useful.
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/v2") || strings.HasPrefix(r.URL.Path, "/api") {
			s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sr.status, "ip", remoteIP(r))
		}
	})
}

// errIsNotFound flattens the two not-found sentinels used across packages.
func errIsNotFound(err error) bool {
	return errors.Is(err, db.ErrNotFound) || errors.Is(err, store.ErrNotFound)
}
