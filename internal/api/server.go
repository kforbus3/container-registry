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

	batch     *batchMigration
	collector *gc.Collector
	sbom      *sbom.Generator
	vuln      *vuln.Scanner
	scheduler *gc.Scheduler
	retention *gc.Retention

	reads   *ratelimit.Limiter
	writes  *ratelimit.Limiter
	hooks   *webhook.Dispatcher
	Metrics *metrics.Registry

	// authFailures throttles wrong credentials, which the request limiters
	// above cannot: they run only once a caller has been identified.
	authFailures *ratelimit.Failures

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
	return "ip:" + s.remoteIP(r)
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
		Metrics: metrics.New(), tokenSecret: secret, batch: &batchMigration{},
		authFailures: ratelimit.NewFailures(
			cfg.AuthFailThreshold, cfg.AuthFailWindow, cfg.AuthLockoutMax),
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
	// Forwarding headers are read only from a proxy named in
	// REGISTRY_TRUSTED_PROXIES: they decide the URL clients are sent to for
	// their credentials, and taking them from anyone would let a caller point
	// that at a host of their choosing.
	if p := s.forwardedValue(r, "X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	host := r.Host
	if h := s.forwardedValue(r, "X-Forwarded-Host"); h != "" {
		host = h
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

// ErrThrottled is returned when a caller has failed authentication too often
// and must wait before trying again.
type ErrThrottled struct{ Retry time.Duration }

func (e *ErrThrottled) Error() string { return "too many failed authentication attempts" }

// resolvePrincipal authenticates a request from an Authorization header or a
// session cookie, throttling repeated failures. It returns nil when no usable
// credential is present.
//
// Every entry point must come through here rather than calling the
// authenticator directly: the per-caller request limit is applied only once a
// principal is known, so this is the sole place a wrong credential can be made
// to cost anything.
func (s *Server) resolvePrincipal(r *http.Request) (*auth.Principal, error) {
	principal, err := s.authenticate(r)

	var throttled *ErrThrottled
	switch {
	case errors.As(err, &throttled):
		// Already waiting; hammering the door does not make the wait longer.
	case errors.Is(err, auth.ErrDisabled), errors.Is(err, auth.ErrTokenInactive):
		// A disabled account and a revoked token are settled facts rather than
		// guesses, so they neither count as failures nor clear earlier ones.
	case err != nil:
		// A caller who presented nothing has nothing to answer for; only a
		// credential that was offered and rejected counts against the limit.
		s.authFailures.Fail(s.authKeys(r)...)
	case principal != nil:
		s.authFailures.Succeed(s.authKeys(r)...)
	}
	return principal, err
}

// authKeys are the identities a failed attempt is counted against: the calling
// address, and the account named by a Basic credential. Counting both bounds
// one host working through a list of accounts and many hosts working on one
// account.
func (s *Server) authKeys(r *http.Request) []string {
	keys := []string{"ip:" + s.remoteIP(r)}
	if user, _, ok := basicUser(r); ok && user != "" {
		keys = append(keys, "user:"+strings.ToLower(user))
	}
	return keys
}

// throttled reports whether this caller is currently waiting out earlier
// failures, but only when a credential is actually being presented: an
// anonymous pull must not be refused because somebody else on the same address
// mistyped a password.
func (s *Server) throttled(r *http.Request) *ErrThrottled {
	if r.Header.Get("Authorization") == "" {
		if c, err := r.Cookie(sessionCookie); err != nil || c.Value == "" {
			return nil
		}
	}
	if blocked, retry := s.authFailures.Blocked(s.authKeys(r)...); blocked {
		return &ErrThrottled{Retry: retry}
	}
	return nil
}

// authThrottleResponse answers a caller that is waiting out failed attempts.
// It is a 429 rather than a 401 so a client stops retrying and a human reading
// the log can tell a locked-out caller from a wrong password.
func (s *Server) authThrottleResponse(w http.ResponseWriter, e *ErrThrottled) {
	seconds := int(e.Retry.Seconds() + 0.999)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	s.ociErr(w, http.StatusTooManyRequests, codeTooManyRequests,
		"too many failed authentication attempts; retry after "+strconv.Itoa(seconds)+"s", nil)
}

// basicUser reads the username from a Basic credential without verifying it.
func basicUser(r *http.Request) (user, pass string, ok bool) {
	hdr := r.Header.Get("Authorization")
	scheme, value, found := strings.Cut(hdr, " ")
	if !found || !strings.EqualFold(scheme, "basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

func (s *Server) authenticate(r *http.Request) (*auth.Principal, error) {
	if t := s.throttled(r); t != nil {
		return nil, t
	}
	if hdr := r.Header.Get("Authorization"); hdr != "" {
		scheme, value, found := strings.Cut(hdr, " ")
		if !found {
			return nil, auth.ErrBadCredentials
		}
		switch strings.ToLower(scheme) {
		case "basic":
			user, pass, ok := basicUser(r)
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
			if p, ok := s.principalFromBearer(r.Context(), raw); ok {
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

// remoteIP extracts the client address, honouring X-Forwarded-For only when the
// peer sending it is a proxy named in REGISTRY_TRUSTED_PROXIES.
//
// The address is not cosmetic: it goes in the audit log, and it is the key a
// caller's failed logins and rate limit are counted against. Taking it from a
// header anyone may set would let a caller choose all three.
func (s *Server) remoteIP(r *http.Request) string {
	direct := directIP(r)
	if !s.Cfg.Trusts(direct) {
		// Nothing vouches for the headers, so the peer on the socket is the
		// only address there is evidence for. Believing X-Forwarded-For from an
		// arbitrary caller would let it pick the address in the audit log and
		// the bucket its failed logins are counted against.
		return direct
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return direct
	}
	// Read right to left. The rightmost entries were appended by proxies whose
	// word we take; the first address that is not one of ours is as far back as
	// the chain can be believed, and everything left of it is client-supplied.
	parts := strings.Split(xff, ",")
	leftmost := ""
	for i := len(parts) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(parts[i])
		if hop == "" {
			continue
		}
		if !s.Cfg.Trusts(hop) {
			return hop
		}
		leftmost = hop
	}
	// Every hop was a proxy we trust — which is always the case with a wildcard
	// trust list. The leftmost is then the closest thing to a client there is;
	// falling back to the peer here would report the nearest proxy instead.
	if leftmost != "" {
		return leftmost
	}
	return direct
}

// directIP is the peer on the socket, with no headers consulted.
func directIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// forwardedValue reads the first entry of a forwarding header, but only from a
// proxy this registry has been told to trust. A chain of proxies appends to
// these, so the first value is the one nearest the client.
func (s *Server) forwardedValue(r *http.Request, header string) string {
	if !s.Cfg.Trusts(directIP(r)) {
		return ""
	}
	v := r.Header.Get(header)
	if v == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(v, ",")[0])
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
	s.DB.Audit(context.WithoutCancel(r.Context()), p.Display(), action, repo, reference, detail, s.remoteIP(r))
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

// contentSecurityPolicy is served with the web UI.
//
// Everything the UI needs is served by this registry, so every fetch directive
// is 'self' and the rest are shut off: no plugins, no <base> rewriting, no
// framing, no form posting elsewhere. That closes the routes an injected string
// would otherwise use to load or exfiltrate anything.
//
// script-src carries 'unsafe-inline' because the UI wires its buttons with
// inline onclick attributes, which no nonce or hash can cover. Removing it
// means moving those handlers to delegated listeners; until then the policy
// still blocks a script from anywhere but this origin, which is what stops an
// injected <script src> from reaching an attacker's host.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"font-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// HSTS is meaningful only over a connection that is already secure —
		// sending it over plain HTTP is ignored by design, and would be a lie
		// on a registry deliberately run without TLS.
		if s.requestIsSecure(r) {
			w.Header().Set("Strict-Transport-Security", s.Cfg.HSTSHeader())
		}
		if strings.HasPrefix(r.URL.Path, "/v2") {
			// A legacy Docker header the OCI specification calls optional and
			// tells clients not to depend on. It is emitted on the registry API
			// only, because some older tooling probes for it.
			w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		} else {
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "same-origin")
			w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsSecure reports whether the client reached the registry over TLS,
// either directly or through a proxy this registry has been told to trust.
func (s *Server) requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := s.forwardedValue(r, "X-Forwarded-Proto"); proto != "" {
		return strings.EqualFold(proto, "https")
	}
	return false
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
			s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sr.status, "ip", s.remoteIP(r))
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
