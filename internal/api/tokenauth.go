package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kforbus3/container-registry/internal/auth"
)

// The Docker token authentication scheme, offered alongside HTTP Basic.
//
// Basic works with every client tested here, and remains the default. But
// Harbor, ECR, GCR and Docker Hub all use the token scheme, so some tooling
// assumes a registry speaks it: the client expects a 401 naming a token
// service, fetches a bearer token scoped to what it is about to do, and retries.
//
// The token service lives in this registry rather than being a separate
// component, so enabling it costs nothing operationally.

// bearerToken is the payload of an issued token. It is signed rather than
// stored: a token is short-lived and self-describing, so validating one must
// not need a database round trip on every blob request.
type bearerToken struct {
	Subject string   `json:"sub"`
	UserID  int64    `json:"uid"`
	TokenID int64    `json:"tid,omitempty"`
	Scopes  []string `json:"scopes"`
	Issued  int64    `json:"iat"`
	Expires int64    `json:"exp"`
}

// scope is one access request: a resource, its name, and the actions wanted.
type scope struct {
	Type    string
	Name    string
	Actions []string
}

// parseScope reads "repository:team-a/app:pull,push".
func parseScope(s string) (scope, bool) {
	parts := strings.Split(s, ":")
	if len(parts) < 3 {
		return scope{}, false
	}
	// A repository name may contain colons in principle; the actions are always
	// the final segment and the type the first.
	actions := parts[len(parts)-1]
	name := strings.Join(parts[1:len(parts)-1], ":")
	if name == "" {
		return scope{}, false
	}
	return scope{
		Type:    parts[0],
		Name:    name,
		Actions: strings.Split(actions, ","),
	}, true
}

func (s scope) String() string {
	return fmt.Sprintf("%s:%s:%s", s.Type, s.Name, strings.Join(s.Actions, ","))
}

// tokenSigningKey derives the key used to sign bearer tokens.
//
// It is derived from a configured secret when one is set, and otherwise from a
// value generated at start-up. A generated key means tokens do not survive a
// restart, which is correct for a single process and visibly wrong for several
// — so running more than one instance requires setting the secret explicitly.
func (s *Server) tokenSigningKey() []byte {
	sum := sha256.Sum256([]byte("registry-bearer-token-v1|" + s.tokenSecret))
	return sum[:]
}

func (s *Server) signToken(t bearerToken) (string, error) {
	payload, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.tokenSigningKey())
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyToken checks a token's signature and expiry.
func (s *Server) verifyToken(raw string) (*bearerToken, error) {
	body, sig, ok := strings.Cut(raw, ".")
	if !ok {
		return nil, fmt.Errorf("malformed token")
	}
	mac := hmac.New(sha256.New, s.tokenSigningKey())
	mac.Write([]byte(body))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return nil, fmt.Errorf("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("malformed token payload")
	}
	var t bearerToken
	if err := json.Unmarshal(payload, &t); err != nil {
		return nil, fmt.Errorf("malformed token payload")
	}
	if time.Now().Unix() > t.Expires {
		return nil, fmt.Errorf("token expired")
	}
	return &t, nil
}

// handleToken issues a bearer token. This is the endpoint named in the
// WWW-Authenticate challenge when token auth is enabled.
//
// The caller authenticates with Basic — a password or an API token — and asks
// for a scope. What comes back is a token carrying only the access the caller
// actually has, so the scope is narrowed here rather than trusted.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, err := s.resolvePrincipal(r)
	var throttled *ErrThrottled
	if errors.As(err, &throttled) {
		s.authThrottleResponse(w, throttled)
		return
	}
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+s.Cfg.Realm+`"`)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	// A token is issued against a real credential. Letting one bearer token buy
	// another would turn a five-minute pull token into an indefinite one by
	// simply asking again before it expires, and would let it widen its own
	// scope on the way.
	if p != nil && p.Bearer {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+s.Cfg.Realm+`"`)
		writeErr(w, http.StatusUnauthorized,
			"a bearer token cannot be exchanged for another; authenticate with a password or API token")
		return
	}
	if p == nil {
		// An anonymous token is still useful: it lets a client pull public
		// repositories through the same code path.
		p = auth.Anonymous()
	}

	requested := r.URL.Query()["scope"]
	granted := make([]string, 0, len(requested))
	for _, raw := range requested {
		sc, ok := parseScope(raw)
		if !ok || sc.Type != "repository" {
			continue
		}
		allowed := make([]string, 0, len(sc.Actions))
		for _, action := range sc.Actions {
			if s.principalMay(r, p, sc.Name, action) {
				allowed = append(allowed, action)
			}
		}
		// A scope the caller has no access to is dropped rather than refused:
		// the specification expects a token listing what was actually granted,
		// and the request that follows will fail on its own merits.
		if len(allowed) > 0 {
			granted = append(granted, scope{Type: sc.Type, Name: sc.Name, Actions: allowed}.String())
		}
	}

	now := time.Now()
	ttl := s.Cfg.TokenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	tok, err := s.signToken(bearerToken{
		Subject: p.Username, UserID: p.UserID, TokenID: p.TokenID,
		Scopes: granted, Issued: now.Unix(), Expires: now.Add(ttl).Unix(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        tok,
		"access_token": tok, // the field name some clients look for
		"expires_in":   int(ttl.Seconds()),
		"issued_at":    now.UTC().Format(time.RFC3339),
	})
}

// principalMay reports whether a principal can perform an action on a
// repository, using the same rules the request path applies.
func (s *Server) principalMay(r *http.Request, p *auth.Principal, repo, verb string) bool {
	var act action
	switch verb {
	case "pull":
		act = actionPull
	case "push":
		act = actionPush
	case "delete":
		act = actionDelete
	default:
		return false
	}
	return s.basicAllows(r, p, repo, act) && s.grantAllows(r, p, repo, act)
}

// basicAllows applies the token-scope and public-repository rules.
func (s *Server) basicAllows(r *http.Request, p *auth.Principal, repo string, act action) bool {
	switch act {
	case actionPull:
		return p.CanPullRepo(repo) || s.repoIsPublic(r, repo)
	case actionPush:
		return p.CanPushRepo(repo)
	case actionDelete:
		return p.CanDeleteRepo(repo)
	}
	return false
}

// principalFromBearer resolves a signed bearer token back into a principal,
// after confirming the account and token behind it are still usable.
func (s *Server) principalFromBearer(ctx context.Context, raw string) (*auth.Principal, bool) {
	t, err := s.verifyToken(raw)
	if err != nil {
		return nil, false
	}
	if !s.Auth.StillValid(ctx, t.UserID, t.TokenID) {
		return nil, false
	}
	p := &auth.Principal{
		UserID: t.UserID, Username: t.Subject, TokenID: t.TokenID,
		RepoPattern: "", // the token's scopes govern instead of a pattern
		Bearer:      true,
	}
	// The granted scopes are the authority. A token with none still resolves to
	// a principal so anonymous pulls of public repositories work, but an empty
	// non-nil slice grants nothing on its own.
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	p.Scopes = t.Scopes
	return p, true
}
