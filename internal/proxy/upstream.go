// Package proxy fetches content from an upstream registry so this one can act
// as a pull-through cache.
//
// The point is Docker Hub's rate limits: an image pulled once is served from
// here forever after, and a build farm counts as one puller rather than
// hundreds.
package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Upstream is a remote registry this one can pull from.
type Upstream struct {
	// URL is the registry root, e.g. https://registry-1.docker.io.
	URL string
	// Username and Password authenticate to the upstream. Docker Hub allows
	// anonymous pulls but at a much lower rate limit, so credentials are worth
	// supplying even for public images.
	Username string
	Password string

	http *http.Client

	// tokens caches per-scope bearer tokens. Upstream registries issue a token
	// per repository scope, and re-fetching one for every blob would triple the
	// request count.
	mu     sync.Mutex
	tokens map[string]*cachedToken
}

type cachedToken struct {
	value   string
	expires time.Time
}

func NewUpstream(url, username, password string, timeout time.Duration) *Upstream {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Upstream{
		URL:      strings.TrimRight(url, "/"),
		Username: username,
		Password: password,
		http:     &http.Client{Timeout: timeout},
		tokens:   map[string]*cachedToken{},
	}
}

// Manifest fetches a manifest by tag or digest, returning its bytes, media type
// and digest.
func (u *Upstream) Manifest(ctx context.Context, repo, reference string, accept []string) ([]byte, string, string, error) {
	path := fmt.Sprintf("/v2/%s/manifests/%s", repo, reference)
	req, err := u.newRequest(ctx, http.MethodGet, path)
	if err != nil {
		return nil, "", "", err
	}
	for _, a := range accept {
		req.Header.Add("Accept", a)
	}
	resp, err := u.doAuthed(ctx, req, repo)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("upstream returned %s for %s", resp.Status, path)
	}
	// 4 MiB matches the manifest bound applied to pushes.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, "", "", err
	}
	return body, resp.Header.Get("Content-Type"), resp.Header.Get("Docker-Content-Digest"), nil
}

// Blob opens a blob for streaming. The caller closes it.
func (u *Upstream) Blob(ctx context.Context, repo, digest string) (io.ReadCloser, int64, error) {
	path := fmt.Sprintf("/v2/%s/blobs/%s", repo, digest)
	req, err := u.newRequest(ctx, http.MethodGet, path)
	if err != nil {
		return nil, 0, err
	}
	resp, err := u.doAuthed(ctx, req, repo)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("upstream returned %s for %s", resp.Status, path)
	}
	return resp.Body, resp.ContentLength, nil
}

func (u *Upstream) newRequest(ctx context.Context, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.URL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "container-registry/proxy")
	return req, nil
}

// doAuthed sends a request, negotiating a bearer token when challenged.
//
// This is the Docker token flow: an unauthenticated request is answered with a
// challenge naming a token service and a scope, a token is fetched for that
// scope, and the request is retried with it.
func (u *Upstream) doAuthed(ctx context.Context, req *http.Request, repo string) (*http.Response, error) {
	scope := "repository:" + repo + ":pull"
	if tok := u.cachedToken(scope); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := u.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	challenge := resp.Header.Get("WWW-Authenticate")
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	token, err := u.fetchToken(ctx, challenge, scope)
	if err != nil {
		return nil, err
	}

	// The original request's body is nil for every call made here, so it can be
	// replayed as-is.
	retry := req.Clone(ctx)
	if token != "" {
		retry.Header.Set("Authorization", "Bearer "+token)
	} else if u.Username != "" {
		retry.SetBasicAuth(u.Username, u.Password)
	}
	return u.http.Do(retry)
}

func (u *Upstream) cachedToken(scope string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	t, ok := u.tokens[scope]
	if !ok || time.Now().After(t.expires) {
		return ""
	}
	return t.value
}

// fetchToken parses a WWW-Authenticate challenge and exchanges it for a token.
func (u *Upstream) fetchToken(ctx context.Context, challenge, scope string) (string, error) {
	params := parseChallenge(challenge)
	realm := params["realm"]
	if realm == "" {
		// A Basic challenge has no token service; the caller falls back to
		// sending credentials directly.
		return "", nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	q.Set("scope", scope)
	req.URL.RawQuery = q.Encode()

	if u.Username != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
			[]byte(u.Username+":"+u.Password)))
	}

	resp, err := u.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token service returned %s", resp.Status)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", err
	}
	token := body.Token
	if token == "" {
		token = body.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("token service returned no token")
	}

	ttl := time.Duration(body.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	u.mu.Lock()
	// Expire early, so a token is never used in the moment it lapses.
	u.tokens[scope] = &cachedToken{value: token, expires: time.Now().Add(ttl - 10*time.Second)}
	u.mu.Unlock()
	return token, nil
}

// parseChallenge splits a WWW-Authenticate value into its parameters.
func parseChallenge(header string) map[string]string {
	out := map[string]string{}
	header = strings.TrimSpace(header)
	if i := strings.IndexByte(header, ' '); i >= 0 {
		out["scheme"] = strings.ToLower(header[:i])
		header = header[i+1:]
	}
	// Parameters are comma-separated key="value" pairs, and a value may itself
	// contain a comma, so the split has to respect quoting.
	var key, value strings.Builder
	inKey, inQuotes := true, false
	flush := func() {
		if k := strings.TrimSpace(key.String()); k != "" {
			out[k] = value.String()
		}
		key.Reset()
		value.Reset()
		inKey = true
	}
	for i := 0; i < len(header); i++ {
		c := header[i]
		switch {
		case inKey && c == '=':
			inKey = false
		case c == '"':
			inQuotes = !inQuotes
		case c == ',' && !inQuotes:
			flush()
		case inKey:
			key.WriteByte(c)
		default:
			value.WriteByte(c)
		}
	}
	flush()
	return out
}
