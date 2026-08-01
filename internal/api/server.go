package api

import (
	"context"
	"crypto/subtle"
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
	"time"

	"github.com/kforbus3/container-registry/internal/auth"
	"github.com/kforbus3/container-registry/internal/config"
	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/gc"
	"github.com/kforbus3/container-registry/internal/metrics"
	"github.com/kforbus3/container-registry/internal/proxy"
	"github.com/kforbus3/container-registry/internal/ratelimit"
	"github.com/kforbus3/container-registry/internal/sbom"
	"github.com/kforbus3/container-registry/internal/store"
	"github.com/kforbus3/container-registry/internal/vuln"
	"github.com/kforbus3/container-registry/internal/webhook"
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

	reads   *ratelimit.Limiter
	writes  *ratelimit.Limiter
	hooks   *webhook.Dispatcher
	Metrics *metrics.Registry

	upstream *proxy.Upstream

	// tokenSecret signs bearer tokens; generated when none is configured.
	tokenSecret string
}

// SetUpstream turns the registry into a pull-through cache for a remote.
func (s *Server) SetUpstream(u *proxy.Upstream) { s.upstream = u }

// proxyRepo reports the upstream repository name for a local one, and whether
// this repository is proxied at all.
//
// Caching is scoped to a prefix so one registry can hold its own images and
// mirror an upstream at the same time: "proxy/library/alpine" is fetched from
// upstream as "library/alpine", while "team-a/app" is purely local.
func (s *Server) proxyRepo(name string) (string, bool) {
	if s.upstream == nil {
		return "", false
	}
	prefix := strings.Trim(s.Cfg.ProxyPrefix, "/")
	if prefix == "" {
		return name, true // the whole registry mirrors upstream
	}
	if name == prefix || !strings.HasPrefix(name, prefix+"/") {
		return "", false
	}
	return strings.TrimPrefix(name, prefix+"/"), true
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
	secret := cfg.TokenSecret
	if secret == "" {
		// A generated key means issued tokens do not survive a restart, which
		// is correct for one process. Running several requires setting the
		// secret so they agree.
		if generated, err := auth.NewSecret(32); err == nil {
			secret = generated
		}
	}
	return &Server{
		Cfg: cfg, DB: database, Store: st, Auth: auth.New(database), Log: log,
		Metrics: metrics.New(), tokenSecret: secret,
	}
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
func (s *Server) challenge(w http.ResponseWriter, r *http.Request, message string) {
	s.challengeScoped(w, r, message, "")
}

// challengeScoped sends the 401 that drives a client to authenticate.
//
// With token auth enabled the challenge names this registry's own token
// service and the scope being attempted, which is what a token-flow client
// needs to fetch a credential for exactly the operation it is retrying.
func (s *Server) challengeScoped(w http.ResponseWriter, r *http.Request, message, scope string) {
	if s.Cfg.TokenAuth {
		challenge := fmt.Sprintf(`Bearer realm=%q,service=%q`, s.tokenRealm(r), s.Cfg.Realm)
		if scope != "" {
			challenge += fmt.Sprintf(`,scope=%q`, scope)
		}
		w.Header().Set("WWW-Authenticate", challenge)
	} else {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+s.Cfg.Realm+`"`)
	}
	s.ociErr(w, http.StatusUnauthorized, codeUnauthorized, message, nil)
}

// tokenRealm returns the absolute URL of the token service.
//
// The realm must be absolute: it is a URL the client fetches directly, and
// clients reject a bare path outright rather than resolving it. Since the
// registry does not know its own public address, an unconfigured realm is
// derived from the request -- which is right for direct access and for a proxy
// that sets the usual forwarding headers. Set REGISTRY_TOKEN_REALM explicitly
// for anything else.
func (s *Server) tokenRealm(r *http.Request) string {
	realm := strings.TrimRight(s.Cfg.TokenRealm, "/")
	if strings.Contains(realm, "://") {
		return realm
	}
	if realm == "" {
		realm = "/token"
	}
	if !strings.HasPrefix(realm, "/") {
		realm = "/" + realm
	}
	if r == nil {
		return realm
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		// Only the first value: a chain of proxies appends to this header.
		scheme = strings.TrimSpace(strings.Split(p, ",")[0])
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	if host == "" {
		return realm
	}
	return scheme + "://" + host + realm
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
			raw := strings.TrimSpace(value)
			// An API token and a registry-issued bearer token both arrive this
			// way; the API token has a recognisable prefix.
			if _, _, ok := auth.SplitToken(raw); ok {
				return s.Auth.AuthenticateToken(r.Context(), raw)
			}
			if p, ok := s.principalFromBearer(raw); ok {
				return p, nil
			}
			return nil, auth.ErrBadCredentials
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

// emit publishes a registry event to any subscribed webhooks. A nil dispatcher
// makes this a no-op, so call sites need no guard.
func (s *Server) emit(r *http.Request, repoID int64, event, repo, reference, digest string) {
	if s.hooks == nil {
		return
	}
	s.hooks.Emit(webhook.Event{
		Event: event, RepoID: repoID,
		Repository: repo, Reference: reference, Digest: digest,
		Actor: principalFrom(r.Context()).Display(),
	})
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
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.Handle("/", s.uiHandler())

	return s.withCommonHeaders(s.withRecovery(s.withLogging(mux)))
}

// handleMetrics serves the Prometheus exposition format.
//
// It is unauthenticated by default because that is what every scraper expects
// and the numbers are counts rather than content; set REGISTRY_METRICS_TOKEN to
// require a bearer token when the endpoint is reachable from outside.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if want := s.Cfg.MetricsToken; want != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			writeErr(w, http.StatusUnauthorized, "metrics token required")
			return
		}
	}
	s.refreshGauges(r)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	s.Metrics.Write(w)
}

// refreshGauges samples the values that describe current state rather than
// accumulated activity.
func (s *Server) refreshGauges(r *http.Request) {
	if st, err := s.DB.Stats(r.Context()); err == nil {
		s.Metrics.SetGauge("registry_repositories", "Repositories in the registry.", nil, float64(st.Repositories))
		s.Metrics.SetGauge("registry_tags", "Tags across all repositories.", nil, float64(st.Tags))
		s.Metrics.SetGauge("registry_manifests", "Manifests stored.", nil, float64(st.Manifests))
		s.Metrics.SetGauge("registry_blobs", "Distinct blobs stored.", nil, float64(st.Blobs))
		s.Metrics.SetGauge("registry_storage_bytes", "Bytes referenced by live manifests.", nil, float64(st.SizeBytes))
		s.Metrics.SetGauge("registry_users", "User accounts.", nil, float64(st.Users))
		s.Metrics.SetGauge("registry_tokens_active", "Tokens that have not been revoked.", nil, float64(st.ActiveTokens))
	}
	if vs, err := s.DB.VulnStats(r.Context()); err == nil {
		s.Metrics.SetGauge("registry_images_scanned", "Images checked against an advisory database.", nil, float64(vs.Scanned))
		for severity, n := range map[string]int{
			"critical": vs.Critical, "high": vs.High, "medium": vs.Medium, "low": vs.Low,
		} {
			s.Metrics.SetGauge("registry_vulnerabilities",
				"Open findings by severity.", metrics.Labels{"severity": severity}, float64(n))
		}
	}
	if s.sbom != nil {
		st := s.sbom.Stats()
		s.Metrics.SetGauge("registry_sbom_generated", "SBOMs published since start-up.", nil, float64(st.Generated))
		s.Metrics.SetGauge("registry_sbom_failed", "SBOM generations that failed.", nil, float64(st.Failed))
	}
	if s.hooks != nil {
		st := s.hooks.Stats()
		s.Metrics.SetGauge("registry_webhook_delivered", "Webhook deliveries that succeeded.", nil, float64(st.Delivered))
		s.Metrics.SetGauge("registry_webhook_failed", "Webhook deliveries that failed.", nil, float64(st.Failed))
		s.Metrics.SetGauge("registry_webhook_dropped", "Events dropped because the queue was full.", nil, float64(st.Dropped))
	}
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
		started := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)

		// Bucket by the kind of request rather than the exact path: a label per
		// repository would give the scrape unbounded cardinality.
		s.Metrics.Inc("registry_requests_total", "Requests served, by kind and status.",
			metrics.Labels{
				"kind":   requestKind(r.URL.Path),
				"method": r.Method,
				"code":   strconv.Itoa(sr.status),
			})
		s.Metrics.Add("registry_request_duration_seconds_sum",
			"Total time spent serving requests, by kind.",
			metrics.Labels{"kind": requestKind(r.URL.Path)}, time.Since(started).Seconds())
		// Static UI assets would drown out anything useful.
		if r.URL.Path == "/" || r.URL.Path == "/token" ||
			strings.HasPrefix(r.URL.Path, "/v2") || strings.HasPrefix(r.URL.Path, "/api") {
			s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sr.status, "ip", remoteIP(r))
		}
	})
}

// requestKind classifies a path into a small fixed set, so metric cardinality
// stays bounded no matter how many repositories exist.
func requestKind(path string) string {
	switch {
	case strings.HasPrefix(path, "/v2/"):
		switch {
		case strings.Contains(path, "/blobs/uploads/"):
			return "blob_upload"
		case strings.Contains(path, "/blobs/"):
			return "blob"
		case strings.Contains(path, "/manifests/"):
			return "manifest"
		case strings.Contains(path, "/tags/"):
			return "tags"
		case strings.Contains(path, "/referrers/"):
			return "referrers"
		}
		return "v2"
	case strings.HasPrefix(path, "/api/"):
		return "api"
	case path == "/metrics":
		return "metrics"
	case path == "/healthz":
		return "health"
	}
	return "ui"
}

// errIsNotFound flattens the two not-found sentinels used across packages.
func errIsNotFound(err error) bool {
	return errors.Is(err, db.ErrNotFound) || errors.Is(err, store.ErrNotFound)
}
