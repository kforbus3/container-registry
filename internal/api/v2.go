package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/kforbus3/container-registry/internal/auth"
	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/sbom"
	"github.com/kforbus3/container-registry/internal/store"
)

// maxManifestBytes bounds a manifest payload. The spec suggests 4 MiB.
const maxManifestBytes = 4 << 20

// action is the permission a /v2 request requires.
type action int

const (
	actionPull action = iota
	actionPush
	actionDelete
)

// serveV2 routes the whole /v2 subtree. Repository names may contain slashes,
// so the path is split on the last routing verb rather than pattern-matched.
func (s *Server) serveV2(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v2/")

	// GET /v2/ — API version check and the endpoint `docker login` probes.
	if rest == "" {
		s.handleVersionCheck(w, r)
		return
	}
	if rest == "_catalog" {
		s.handleCatalog(w, r)
		return
	}

	segments := strings.Split(rest, "/")
	verbIdx := -1
	for i := len(segments) - 1; i > 0; i-- {
		switch segments[i] {
		case "blobs", "manifests", "tags", "referrers":
			verbIdx = i
		}
		if verbIdx >= 0 {
			break
		}
	}
	if verbIdx <= 0 {
		s.ociErr(w, http.StatusNotFound, codeUnsupported, "unsupported endpoint", nil)
		return
	}

	name := strings.Join(segments[:verbIdx], "/")
	tail := segments[verbIdx:]

	if !validRepoName(name) {
		s.ociErr(w, http.StatusBadRequest, codeNameInvalid, "invalid repository name", name)
		return
	}

	switch {
	case len(tail) == 2 && tail[0] == "tags" && tail[1] == "list":
		s.guard(w, r, name, actionPull, func(w http.ResponseWriter, r *http.Request) {
			s.handleTagsList(w, r, name)
		})

	case len(tail) == 2 && tail[0] == "manifests":
		ref, err := url.PathUnescape(tail[1])
		if err != nil {
			s.ociErr(w, http.StatusBadRequest, codeManifestInvalid, "invalid reference", nil)
			return
		}
		act := actionPull
		switch r.Method {
		case http.MethodPut:
			act = actionPush
		case http.MethodDelete:
			act = actionDelete
		}
		s.guard(w, r, name, act, func(w http.ResponseWriter, r *http.Request) {
			s.handleManifest(w, r, name, ref)
		})

	case len(tail) == 2 && tail[0] == "referrers":
		s.guard(w, r, name, actionPull, func(w http.ResponseWriter, r *http.Request) {
			s.handleReferrers(w, r, name, tail[1])
		})

	// POST /v2/<name>/blobs/uploads/  (trailing slash yields an empty segment)
	case tail[0] == "blobs" && len(tail) >= 2 && tail[1] == "uploads" &&
		(len(tail) == 2 || (len(tail) == 3 && tail[2] == "")):
		s.guard(w, r, name, actionPush, func(w http.ResponseWriter, r *http.Request) {
			s.handleUploadStart(w, r, name)
		})

	case tail[0] == "blobs" && len(tail) == 3 && tail[1] == "uploads":
		s.guard(w, r, name, actionPush, func(w http.ResponseWriter, r *http.Request) {
			s.handleUploadSession(w, r, name, tail[2])
		})

	case len(tail) == 2 && tail[0] == "blobs":
		act := actionPull
		if r.Method == http.MethodDelete {
			act = actionDelete
		}
		s.guard(w, r, name, act, func(w http.ResponseWriter, r *http.Request) {
			s.handleBlob(w, r, name, tail[1])
		})

	default:
		s.ociErr(w, http.StatusNotFound, codeUnsupported, "unsupported endpoint", nil)
	}
}

// guard authenticates the caller and checks the requested action against the
// repository before invoking next.
func (s *Server) guard(w http.ResponseWriter, r *http.Request, repo string, act action, next http.HandlerFunc) {
	// The challenge names the scope being attempted, which is what tells a
	// token-flow client what to ask its token service for. Without it the
	// client fetches a scopeless token and is then refused forever.
	want := scopeFor(repo, act)

	p, err := s.resolvePrincipal(r)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrDisabled):
			s.challengeScoped(w, r, "account is disabled", want)
		case errors.Is(err, auth.ErrTokenInactive):
			s.challengeScoped(w, r, "token is revoked or expired", want)
		default:
			s.challengeScoped(w, r, "authentication required", want)
		}
		return
	}

	if p == nil {
		// No credential supplied. Anonymous pull is allowed only for reads of
		// a repository that has been marked public.
		if act == actionPull && s.Cfg.AllowAnonymousPull && s.repoIsPublic(r, repo) {
			p = auth.Anonymous()
		} else {
			s.challengeScoped(w, r, "authentication required", want)
			return
		}
	}

	allowed := false
	switch act {
	case actionPull:
		allowed = p.CanPullRepo(repo)
		if !allowed && s.repoIsPublic(r, repo) {
			allowed = true // public repositories are readable by any authenticated caller
		}
	case actionPush:
		allowed = p.CanPushRepo(repo)
	case actionDelete:
		allowed = p.CanDeleteRepo(repo)
	}
	if allowed {
		// Repository grants narrow access further. A repository with no grants
		// is ungoverned and behaves exactly as before, so this only bites where
		// somebody has deliberately locked one down.
		allowed = s.grantAllows(r, p, repo, act)
	}
	if !allowed {
		if p.IsAnonymous() {
			s.challengeScoped(w, r, "authentication required", want)
			return
		}
		// A bearer token that simply does not carry this scope is answered with
		// a challenge rather than a refusal, so the client can fetch one that
		// does. That is how the token flow is meant to escalate; a flat 403
		// would strand a client holding a token for a different repository.
		if p.Scopes != nil {
			s.challengeScoped(w, r, "token does not grant "+want, want)
			return
		}
		s.ociErr(w, http.StatusForbidden, codeDenied,
			fmt.Sprintf("insufficient permission for %s on repository %q", actionName(act), repo), nil)
		return
	}

	r = r.WithContext(withPrincipal(r.Context(), p))
	// Applied after authentication so an authenticated caller is limited as
	// itself rather than sharing a bucket with everyone behind the same address.
	if !s.allowRequest(w, r) {
		return
	}
	next(w, r)
}

// grantAllows applies per-repository access grants.
//
// Registry administrators are never locked out — otherwise a mistaken grant
// could make a repository unadministrable — and a public repository stays
// readable, because that is what public means.
func (s *Server) grantAllows(r *http.Request, p *auth.Principal, name string, act action) bool {
	if p.Admin {
		return true
	}
	repo, err := s.DB.GetRepository(r.Context(), name)
	if err != nil {
		return true // nothing to govern yet
	}
	role, governed, err := s.DB.RepoAccess(r.Context(), repo.ID, p.UserID)
	if err != nil || !governed {
		return true
	}
	need := db.RoleRead
	switch act {
	case actionPush:
		need = db.RoleWrite
	case actionDelete:
		need = db.RoleAdmin
	}
	if act == actionPull && repo.Public {
		return true
	}
	return db.RoleRank(role) >= db.RoleRank(need)
}

// scopeFor renders the access scope a request needs, in the form a token
// service expects.
func scopeFor(repo string, act action) string {
	switch act {
	case actionPush:
		// A push reads as well as writes, so clients ask for both together.
		return "repository:" + repo + ":pull,push"
	case actionDelete:
		return "repository:" + repo + ":delete"
	}
	return "repository:" + repo + ":pull"
}

func actionName(a action) string {
	switch a {
	case actionPush:
		return "push"
	case actionDelete:
		return "delete"
	}
	return "pull"
}

func (s *Server) repoIsPublic(r *http.Request, name string) bool {
	repo, err := s.DB.GetRepository(r.Context(), name)
	return err == nil && repo.Public
}

// ---------------------------------------------------------------- version & catalog

func (s *Server) handleVersionCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.ociErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed", nil)
		return
	}
	p, err := s.resolvePrincipal(r)
	if err != nil {
		s.challenge(w, r, "invalid credentials")
		return
	}
	if p == nil && !s.Cfg.AllowAnonymousPull {
		// A 401 with a Basic challenge is what drives `docker login`.
		s.challenge(w, r, "authentication required")
		return
	}
	// This endpoint resolves its own principal rather than going through the
	// guard, so the limit has to be applied here as well.
	r = r.WithContext(withPrincipal(r.Context(), p))
	if !s.allowRequest(w, r) {
		return
	}
	if p != nil && !p.IsAnonymous() {
		s.DB.Audit(r.Context(), p.Display(), "login", "", "", "api version check", remoteIP(r))
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	p, err := s.resolvePrincipal(r)
	if err != nil || (p == nil && !s.Cfg.AllowAnonymousPull) {
		s.challenge(w, r, "authentication required")
		return
	}
	if p == nil {
		p = auth.Anonymous()
	}
	r = r.WithContext(withPrincipal(r.Context(), p))
	if !s.allowRequest(w, r) {
		return
	}
	n, last := paginationParams(r)
	if n == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"repositories": []string{}})
		return
	}

	// Over-fetch so filtering by visibility still fills a page where possible.
	fetch := n
	if fetch > 0 {
		fetch = n * 4
	}
	names, err := s.DB.CatalogNames(r.Context(), last, fetch)
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to list repositories", nil)
		return
	}

	visible := make([]string, 0, len(names))
	for _, name := range names {
		if p.CanPullRepo(name) || s.repoIsPublic(r, name) {
			visible = append(visible, name)
		}
		if n > 0 && len(visible) == n {
			break
		}
	}

	if n > 0 && len(visible) == n {
		// Signal that more results may exist.
		next := *r.URL
		q := next.Query()
		q.Set("n", strconv.Itoa(n))
		q.Set("last", visible[len(visible)-1])
		next.RawQuery = q.Encode()
		w.Header().Set("Link", `<`+next.RequestURI()+`>; rel="next"`)
	}
	writeJSON(w, http.StatusOK, map[string]any{"repositories": visible})
}

// noLimit is the sentinel for "the client did not ask for a page size". It is
// distinct from n=0, which the specification defines as an explicit request for
// an empty list.
const noLimit = -1

func paginationParams(r *http.Request) (n int, last string) {
	last = r.URL.Query().Get("last")
	v := r.URL.Query().Get("n")
	if v == "" {
		return noLimit, last
	}
	parsed, err := strconv.Atoi(v)
	if err != nil || parsed < 0 {
		return noLimit, last
	}
	if parsed > 1000 {
		parsed = 1000
	}
	return parsed, last
}

// ---------------------------------------------------------------- tags

func (s *Server) handleTagsList(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		s.ociErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed", nil)
		return
	}
	repo, err := s.DB.GetRepository(r.Context(), name)
	if err != nil {
		s.ociErr(w, http.StatusNotFound, codeNameUnknown, "repository not found", name)
		return
	}
	n, last := paginationParams(r)
	// "When n is zero, this endpoint MUST return an empty list, and MUST NOT
	// include a Link header."
	if n == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "tags": []string{}})
		return
	}
	tags, err := s.DB.TagNames(r.Context(), repo.ID, last, n)
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to list tags", nil)
		return
	}
	if n > 0 && len(tags) == n {
		next := *r.URL
		q := next.Query()
		q.Set("n", strconv.Itoa(n))
		q.Set("last", tags[len(tags)-1])
		next.RawQuery = q.Encode()
		w.Header().Set("Link", `<`+next.RequestURI()+`>; rel="next"`)
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "tags": tags})
}

// ---------------------------------------------------------------- manifests

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.getManifest(w, r, name, ref)
	case http.MethodPut:
		s.putManifest(w, r, name, ref)
	case http.MethodDelete:
		s.deleteManifest(w, r, name, ref)
	default:
		s.ociErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed", nil)
	}
}

// resolveRef turns a tag or digest reference into a manifest digest.
func (s *Server) resolveRef(r *http.Request, repoID int64, ref string) (string, error) {
	if store.ValidDigest(ref) {
		return ref, nil
	}
	if !validTag(ref) {
		return "", fmt.Errorf("invalid reference")
	}
	t, err := s.DB.GetTag(r.Context(), repoID, ref)
	if err != nil {
		return "", err
	}
	return t.Digest, nil
}

func (s *Server) getManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	repo, err := s.DB.GetRepository(r.Context(), name)
	if err != nil {
		// A proxied repository is created on first fetch, so a miss here is
		// not necessarily an error.
		if !s.tryCacheManifest(r, name, ref) {
			s.ociErr(w, http.StatusNotFound, codeNameUnknown, "repository not found", name)
			return
		}
		if repo, err = s.DB.GetRepository(r.Context(), name); err != nil {
			s.ociErr(w, http.StatusNotFound, codeNameUnknown, "repository not found", name)
			return
		}
	}
	digest, err := s.resolveRef(r, repo.ID, ref)
	if err != nil {
		if !s.tryCacheManifest(r, name, ref) {
			s.ociErr(w, http.StatusNotFound, codeManifestUnknown, "manifest unknown", ref)
			return
		}
		if digest, err = s.resolveRef(r, repo.ID, ref); err != nil {
			s.ociErr(w, http.StatusNotFound, codeManifestUnknown, "manifest unknown", ref)
			return
		}
	}
	m, err := s.DB.GetManifest(r.Context(), repo.ID, digest)
	if err != nil {
		s.ociErr(w, http.StatusNotFound, codeManifestUnknown, "manifest unknown", ref)
		return
	}
	body, err := s.Store.For(name).ReadAll(digest)
	if err != nil {
		s.ociErr(w, http.StatusNotFound, codeManifestUnknown, "manifest content missing", ref)
		return
	}
	// Honour Accept when the client lists media types, as the spec requires.
	// Clients commonly send one media type per header line rather than a single
	// comma-separated value, so every line must be considered.
	if accept := r.Header.Values("Accept"); len(accept) > 0 && !acceptMatches(accept, m.MediaType) {
		s.ociErr(w, http.StatusNotFound, codeManifestUnknown,
			fmt.Sprintf("manifest is %s, which the client did not accept", m.MediaType), nil)
		return
	}

	w.Header().Set("Content-Type", m.MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Etag", `"`+digest+`"`)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// acceptMatches reports whether any of the Accept header values admits the
// media type. Each value may itself be a comma-separated list.
func acceptMatches(accept []string, mediaType string) bool {
	empty := true
	for _, header := range accept {
		for _, part := range strings.Split(header, ",") {
			v := strings.TrimSpace(part)
			if i := strings.IndexByte(v, ';'); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			if v == "" {
				continue
			}
			empty = false
			if v == "*/*" || strings.EqualFold(v, mediaType) {
				return true
			}
			// Handle "application/*" style wildcards.
			if strings.HasSuffix(v, "/*") &&
				strings.HasPrefix(strings.ToLower(mediaType), strings.ToLower(strings.TrimSuffix(v, "*"))) {
				return true
			}
		}
	}
	// An Accept header that carried no usable value constrains nothing.
	return empty
}

func (s *Server) putManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	isDigestRef := store.ValidDigest(ref)
	if !isDigestRef && !validTag(ref) {
		s.ociErr(w, http.StatusBadRequest, codeManifestInvalid, "invalid tag", ref)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxManifestBytes+1))
	if err != nil {
		s.ociErr(w, http.StatusBadRequest, codeManifestInvalid, "failed to read manifest body", nil)
		return
	}
	if len(body) > maxManifestBytes {
		s.ociErr(w, http.StatusRequestEntityTooLarge, codeManifestInvalid, "manifest exceeds 4 MiB", nil)
		return
	}
	if len(body) == 0 {
		s.ociErr(w, http.StatusBadRequest, codeManifestInvalid, "empty manifest body", nil)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = strings.TrimSpace(contentType[:i])
	}
	parsed, err := parseManifest(body, contentType)
	if err != nil {
		s.ociErr(w, http.StatusBadRequest, codeManifestInvalid, err.Error(), nil)
		return
	}

	// Name the manifest with the algorithm the client used to address it, so a
	// client working in sha512 can round-trip its own digests. A tag push has
	// no such hint, so it gets the mandatory sha256.
	algo := "sha256"
	if isDigestRef {
		algo = store.DigestAlgorithm(ref)
	}
	digest, err := store.DigestWith(algo, body)
	if err != nil {
		s.ociErr(w, http.StatusBadRequest, codeDigestInvalid, err.Error(), nil)
		return
	}
	if isDigestRef && ref != digest {
		s.ociErr(w, http.StatusBadRequest, codeDigestInvalid,
			fmt.Sprintf("reference digest %s does not match content digest %s", ref, digest), nil)
		return
	}

	repo, err := s.DB.EnsureRepository(r.Context(), name)
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to create repository", nil)
		return
	}

	// Immutable repositories accept new tags but never a tag reassignment.
	if !isDigestRef && repo.Immutable {
		if existing, err := s.DB.GetTag(r.Context(), repo.ID, ref); err == nil && existing.Digest != digest {
			s.ociErr(w, http.StatusConflict, codeDenied,
				fmt.Sprintf("repository %q is immutable; tag %q already points at %s", name, ref, existing.Digest), nil)
			return
		}
	}

	// Every referenced blob or child manifest must already be present in this
	// repository. Clients upload layers (or cross-repo mount them) first.
	for _, ref := range parsed.Refs {
		switch ref.Kind {
		case "foreign":
			continue // non-distributable layers are fetched from their URLs
		case "manifest":
			if _, err := s.DB.GetManifest(r.Context(), repo.ID, ref.Digest); err != nil {
				s.ociErr(w, http.StatusNotFound, codeManifestBlobUnknown,
					"referenced manifest is not present in this repository", ref.Digest)
				return
			}
		default:
			_, linked, err := s.DB.BlobLinked(r.Context(), repo.ID, ref.Digest)
			if err != nil {
				s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to check blob", nil)
				return
			}
			if !linked || !s.Store.For(name).Exists(ref.Digest) {
				s.ociErr(w, http.StatusNotFound, codeManifestBlobUnknown,
					"referenced blob is not present in this repository", ref.Digest)
				return
			}
		}
	}

	if _, err := s.Store.For(name).PutBytesWith(algo, body); err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to store manifest", nil)
		return
	}
	m := &db.Manifest{
		RepoID:       repo.ID,
		Digest:       digest,
		MediaType:    parsed.MediaType,
		ArtifactType: parsed.ArtifactType,
		Subject:      parsed.Subject,
		Size:         int64(len(body)),
		ConfigDigest: parsed.ConfigDigest,
	}
	if err := s.DB.PutManifest(r.Context(), m, parsed.Refs); err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to record manifest", nil)
		return
	}
	// The manifest is itself a blob of the repository, so garbage collection
	// and size accounting see it.
	s.DB.LinkBlob(r.Context(), repo.ID, digest, int64(len(body)))

	if !isDigestRef {
		if err := s.DB.PutTag(r.Context(), repo.ID, ref, digest); err != nil {
			s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to record tag", nil)
			return
		}
		s.audit(r, "push.tag", name, ref, digest)
		s.emit(r, repo.ID, db.EventPushTag, name, ref, digest)
	} else {
		s.audit(r, "push.manifest", name, digest, parsed.MediaType)
		s.emit(r, repo.ID, db.EventPushManifest, name, digest, digest)
		// Optional spec feature: a manifest pushed by digest may carry `tag`
		// query parameters, letting a client publish several tags in one
		// request. Each accepted tag is echoed in an OCI-Tag header.
		if accepted, err := s.applyTagParams(r, repo, digest); err != nil {
			s.ociErr(w, http.StatusBadRequest, codeManifestInvalid, err.Error(), nil)
			return
		} else if len(accepted) > 0 {
			w.Header().Add("OCI-Tag", strings.Join(accepted, ", "))
		}
	}

	// Describe the image in the background. Enqueueing never blocks, so a slow
	// or saturated scanner cannot delay the push acknowledgement.
	if s.sbom != nil {
		s.sbom.Enqueue(sbom.Job{RepoID: repo.ID, RepoName: name, Digest: digest})
	}

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, digest))
	w.Header().Set("Docker-Content-Digest", digest)
	if parsed.Subject != "" {
		// Tells the client the referrers API reflects this manifest.
		w.Header().Set("OCI-Subject", parsed.Subject)
	}
	w.WriteHeader(http.StatusCreated)
}

// maxTagParams bounds how many tags one push may create. The spec asks for at
// least 10 and allows a registry to refuse more.
const maxTagParams = 32

// applyTagParams creates the tags named by `tag` query parameters on a
// push-by-digest, returning the tags it accepted.
func (s *Server) applyTagParams(r *http.Request, repo *db.Repository, digest string) ([]string, error) {
	tags := r.URL.Query()["tag"]
	if len(tags) == 0 {
		return nil, nil
	}
	if len(tags) > maxTagParams {
		return nil, fmt.Errorf("at most %d tag parameters are accepted", maxTagParams)
	}
	accepted := make([]string, 0, len(tags))
	for _, t := range tags {
		if !validTag(t) {
			return nil, fmt.Errorf("invalid tag %q", t)
		}
		if repo.Immutable {
			if existing, err := s.DB.GetTag(r.Context(), repo.ID, t); err == nil && existing.Digest != digest {
				return nil, fmt.Errorf("repository is immutable and tag %q already points elsewhere", t)
			}
		}
		if err := s.DB.PutTag(r.Context(), repo.ID, t, digest); err != nil {
			return nil, fmt.Errorf("failed to record tag %q", t)
		}
		s.audit(r, "push.tag", repo.Name, t, digest)
		accepted = append(accepted, t)
	}
	return accepted, nil
}

func (s *Server) deleteManifest(w http.ResponseWriter, r *http.Request, name, ref string) {
	repo, err := s.DB.GetRepository(r.Context(), name)
	if err != nil {
		s.ociErr(w, http.StatusNotFound, codeNameUnknown, "repository not found", name)
		return
	}
	// Deleting by tag removes only the tag; deleting by digest removes the
	// manifest and every tag pointing at it. This matches the spec.
	if !store.ValidDigest(ref) {
		if _, err := s.DB.GetTag(r.Context(), repo.ID, ref); err != nil {
			s.ociErr(w, http.StatusNotFound, codeManifestUnknown, "tag unknown", ref)
			return
		}
		if err := s.DB.DeleteTag(r.Context(), repo.ID, ref); err != nil {
			s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to delete tag", nil)
			return
		}
		s.audit(r, "delete.tag", name, ref, "")
		s.emit(r, repo.ID, db.EventDeleteTag, name, ref, "")
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if _, err := s.DB.GetManifest(r.Context(), repo.ID, ref); err != nil {
		s.ociErr(w, http.StatusNotFound, codeManifestUnknown, "manifest unknown", ref)
		return
	}
	if err := s.DB.DeleteManifest(r.Context(), repo.ID, ref); err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to delete manifest", nil)
		return
	}
	s.audit(r, "delete.manifest", name, ref, "")
	s.emit(r, repo.ID, db.EventDeleteManifest, name, ref, ref)
	w.WriteHeader(http.StatusAccepted)
}

// ---------------------------------------------------------------- referrers

func (s *Server) handleReferrers(w http.ResponseWriter, r *http.Request, name, digest string) {
	if r.Method != http.MethodGet {
		s.ociErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed", nil)
		return
	}
	if !store.ValidDigest(digest) {
		s.ociErr(w, http.StatusBadRequest, codeDigestInvalid, "invalid digest", digest)
		return
	}
	idx := referrersIndex{SchemaVersion: 2, MediaType: MediaTypeOCIIndex, Manifests: []descriptor{}}
	artifactType := r.URL.Query().Get("artifactType")

	// The spec requires an empty index rather than an error when the subject
	// has no referrers, and treats an unknown repository the same way: a 404 is
	// reserved for registries that do not implement the referrers API at all.
	repo, err := s.DB.GetRepository(r.Context(), name)
	if err != nil {
		if !errIsNotFound(err) {
			s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to look up repository", nil)
			return
		}
		s.writeReferrers(w, idx, artifactType)
		return
	}

	manifests, err := s.DB.Referrers(r.Context(), repo.ID, digest, artifactType)
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to list referrers", nil)
		return
	}

	for _, m := range manifests {
		d := descriptor{MediaType: m.MediaType, Digest: m.Digest, Size: m.Size, ArtifactType: m.ArtifactType}
		// Surface annotations so clients can filter without fetching each one.
		if body, err := s.Store.For(name).ReadAll(m.Digest); err == nil {
			var doc manifestDoc
			if json.Unmarshal(body, &doc) == nil && len(doc.Annotations) > 0 {
				d.Annotations = doc.Annotations
			}
		}
		idx.Manifests = append(idx.Manifests, d)
	}
	s.writeReferrers(w, idx, artifactType)
}

// writeReferrers emits a referrers index with the media type the spec mandates.
func (s *Server) writeReferrers(w http.ResponseWriter, idx referrersIndex, artifactType string) {
	if artifactType != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	w.Header().Set("Content-Type", MediaTypeOCIIndex)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(idx)
}

// ---------------------------------------------------------------- blobs

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	if !store.ValidDigest(digest) {
		s.ociErr(w, http.StatusBadRequest, codeDigestInvalid, "invalid digest", digest)
		return
	}
	repo, err := s.DB.GetRepository(r.Context(), name)
	if err != nil {
		s.ociErr(w, http.StatusNotFound, codeNameUnknown, "repository not found", name)
		return
	}
	_, linked, err := s.DB.BlobLinked(r.Context(), repo.ID, digest)
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to look up blob", nil)
		return
	}
	if !linked {
		// Fill from the upstream when this repository is proxied.
		if !s.tryCacheBlob(r, name, digest) {
			s.ociErr(w, http.StatusNotFound, codeBlobUnknown, "blob unknown to this repository", digest)
			return
		}
	}

	switch r.Method {
	case http.MethodDelete:
		if err := s.DB.UnlinkBlob(r.Context(), repo.ID, digest); err != nil {
			s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to delete blob", nil)
			return
		}
		s.audit(r, "delete.blob", name, digest, "")
		w.WriteHeader(http.StatusAccepted)
		return

	case http.MethodHead:
		size, _, err := s.Store.For(name).Stat(digest)
		if err != nil {
			s.ociErr(w, http.StatusNotFound, codeBlobUnknown, "blob content missing", digest)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
		return

	case http.MethodGet:
		size, _, err := s.Store.For(name).Stat(digest)
		if err != nil {
			s.ociErr(w, http.StatusNotFound, codeBlobUnknown, "blob content missing", digest)
			return
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.Header().Set("Content-Type", "application/octet-stream")
		// Blobs are immutable, so they can be cached indefinitely.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Etag", `"`+digest+`"`)
		w.Header().Set("Accept-Ranges", "bytes")
		s.serveBlobRange(w, r, name, digest, size)
		return

	default:
		s.ociErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed", nil)
	}
}

// serveBlobRange writes a blob, honouring a single byte range.
//
// Ranges are handled here rather than by http.ServeContent because a blob may
// live in an object store, which returns a stream and not a seekable file.
// Multi-range requests are answered in full, which the specification permits
// and no registry client asks for.
func (s *Server) serveBlobRange(w http.ResponseWriter, r *http.Request, name, digest string, size int64) {
	start, end, ok, satisfiable := parseByteRange(r.Header.Get("Range"), size)
	if !satisfiable {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		s.ociErr(w, http.StatusRequestedRangeNotSatisfiable, codeBlobUnknown,
			"requested range is outside the blob", nil)
		return
	}

	if !ok {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		rc, err := s.Store.For(name).Open2(digest)
		if err != nil {
			return // headers are already sent; the truncated body signals failure
		}
		defer rc.Close()
		io.Copy(w, rc)
		return
	}

	length := end - start + 1
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.WriteHeader(http.StatusPartialContent)

	rc, err := s.Store.For(name).OpenRange(digest, start, length)
	if err != nil {
		return
	}
	defer rc.Close()
	io.Copy(w, rc)
}

// parseByteRange reads a single "bytes=" range against a known size.
//
// ok reports whether a range was requested at all; satisfiable reports whether
// it can be served, which is the difference between 200 and 416.
func parseByteRange(header string, size int64) (start, end int64, ok, satisfiable bool) {
	header = strings.TrimSpace(header)
	if header == "" || !strings.HasPrefix(header, "bytes=") {
		return 0, 0, false, true
	}
	spec := strings.TrimPrefix(header, "bytes=")
	// Only the first range of a multi-range request is considered; the rest
	// fall back to serving the whole blob.
	if strings.Contains(spec, ",") {
		return 0, 0, false, true
	}
	first, last, found := strings.Cut(spec, "-")
	if !found {
		return 0, 0, false, true
	}
	first, last = strings.TrimSpace(first), strings.TrimSpace(last)

	switch {
	case first == "" && last == "":
		return 0, 0, false, true
	case first == "":
		// A suffix range: the final N bytes.
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, false, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true, true
	default:
		start, err := strconv.ParseInt(first, 10, 64)
		if err != nil || start < 0 {
			return 0, 0, false, false
		}
		if start >= size {
			return 0, 0, false, false
		}
		end := size - 1
		if last != "" {
			end, err = strconv.ParseInt(last, 10, 64)
			if err != nil || end < start {
				return 0, 0, false, false
			}
			if end >= size {
				end = size - 1
			}
		}
		return start, end, true, true
	}
}

// ---------------------------------------------------------------- uploads

func (s *Server) handleUploadStart(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		s.ociErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed", nil)
		return
	}
	repo, err := s.DB.EnsureRepository(r.Context(), name)
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to create repository", nil)
		return
	}
	q := r.URL.Query()

	// end-4c: a client pushing under a non-sha256 algorithm SHOULD announce it
	// here. Every supported algorithm is computed during the upload regardless,
	// so this only needs validating — but an unsupported one must fail now
	// rather than after the client has streamed a whole layer.
	if algo := q.Get("digest-algorithm"); algo != "" {
		if !slices.Contains(store.SupportedAlgorithms, algo) {
			s.ociErr(w, http.StatusBadRequest, codeDigestInvalid,
				fmt.Sprintf("unsupported digest algorithm %q; this registry supports %s",
					algo, strings.Join(store.SupportedAlgorithms, ", ")), nil)
			return
		}
	}

	// Cross-repository blob mount: reuse an existing blob without re-uploading.
	if mount := q.Get("mount"); mount != "" {
		if s.tryMount(w, r, repo, name, mount, q.Get("from")) {
			return
		}
		// Fall through to a normal upload session, as the spec requires.
	}

	// Monolithic upload: POST with ?digest= and the whole body.
	if digest := q.Get("digest"); digest != "" {
		s.completeUpload(w, r, repo, name, "", digest, r.Body)
		return
	}

	up, err := s.Store.NewUpload()
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeBlobUploadInvalid, "failed to start upload", nil)
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, up.ID))
	w.Header().Set("Range", "0-0")
	w.Header().Set("Docker-Upload-UUID", up.ID)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusAccepted)
}

// tryMount links an existing blob into the target repository. It reports
// whether it produced a response.
func (s *Server) tryMount(w http.ResponseWriter, r *http.Request, repo *db.Repository, name, digest, from string) bool {
	if !store.ValidDigest(digest) {
		return false
	}
	// Mounting links a blob into another repository without moving bytes, so
	// it is only valid within one backend. Across a storage boundary the target
	// would advertise a blob whose bytes are in a bucket it never reads -- a
	// broken pull, and where the boundary is a jurisdiction, content escaping
	// the region it was confined to. Declining falls back to a normal upload,
	// which puts the bytes where they belong.
	if from != "" && !s.Store.Router().SameBackend(from, name) {
		return false
	}
	// Existence is checked where the bytes would actually come from.
	source := name
	if from != "" {
		source = from
	}
	if !s.Store.For(source).Exists(digest) {
		return false
	}
	p := principalFrom(r.Context())
	// The caller must be able to read the source repository, otherwise a mount
	// would let anyone copy a blob out of a repository they cannot see.
	if from != "" {
		src, err := s.DB.GetRepository(r.Context(), from)
		if err != nil {
			return false
		}
		if !p.CanPullRepo(from) && !src.Public {
			return false
		}
		if _, linked, err := s.DB.BlobLinked(r.Context(), src.ID, digest); err != nil || !linked {
			return false
		}
	} else if !p.Admin {
		// Without a source repository there is nothing to authorise against.
		return false
	}

	size, ok, err := s.DB.AnyBlobLink(r.Context(), digest)
	if err != nil || !ok {
		if fsSize, _, statErr := s.Store.For(source).Stat(digest); statErr == nil {
			size = fsSize
		} else {
			return false
		}
	}
	if err := s.DB.LinkBlob(r.Context(), repo.ID, digest, size); err != nil {
		return false
	}
	s.audit(r, "mount.blob", name, digest, "from "+from)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
	return true
}

func (s *Server) handleUploadSession(w http.ResponseWriter, r *http.Request, name, id string) {
	repo, err := s.DB.EnsureRepository(r.Context(), name)
	if err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to create repository", nil)
		return
	}

	switch r.Method {
	case http.MethodGet:
		up, err := s.Store.UploadStatus(id)
		if err != nil {
			s.ociErr(w, http.StatusNotFound, codeBlobUploadUnknown, "upload unknown", id)
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id))
		w.Header().Set("Range", rangeHeader(up.Offset))
		w.Header().Set("Docker-Upload-UUID", id)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodPatch:
		expected := int64(-1)
		if cr := r.Header.Get("Content-Range"); cr != "" {
			start, _, err := parseContentRange(cr)
			if err != nil {
				s.ociErr(w, http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid, err.Error(), nil)
				return
			}
			expected = start
		}
		up, err := s.Store.Append(id, r.Body, expected)
		if err != nil {
			s.uploadError(w, err, id)
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, id))
		w.Header().Set("Range", rangeHeader(up.Offset))
		w.Header().Set("Docker-Upload-UUID", id)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusAccepted)

	case http.MethodPut:
		digest := r.URL.Query().Get("digest")
		if digest == "" {
			s.ociErr(w, http.StatusBadRequest, codeDigestInvalid, "digest query parameter is required", nil)
			return
		}
		// A closing PUT may carry a final chunk, and that chunk is subject to
		// the same ordering rule as a PATCH: an offset that does not continue
		// the upload is a range error, not a digest error.
		expected := int64(-1)
		if cr := r.Header.Get("Content-Range"); cr != "" {
			start, _, err := parseContentRange(cr)
			if err != nil {
				s.ociErr(w, http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid, err.Error(), nil)
				return
			}
			expected = start
		}
		s.completeUploadAt(w, r, repo, name, id, digest, r.Body, expected)

	case http.MethodDelete:
		if err := s.Store.Cancel(id); err != nil {
			s.ociErr(w, http.StatusNotFound, codeBlobUploadUnknown, "upload unknown", id)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		s.ociErr(w, http.StatusMethodNotAllowed, codeUnsupported, "method not allowed", nil)
	}
}

// completeUpload finishes an upload session (or performs a single-request
// upload when id is empty) and links the blob into the repository.
func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request, repo *db.Repository,
	name, id, digest string, body io.Reader) {
	s.completeUploadAt(w, r, repo, name, id, digest, body, -1)
}

// completeUploadAt is completeUpload with an expected starting offset for the
// final chunk. A negative offset means "append wherever the session is".
func (s *Server) completeUploadAt(w http.ResponseWriter, r *http.Request, repo *db.Repository,
	name, id, digest string, body io.Reader, expectedOffset int64) {

	if !store.ValidDigest(digest) {
		s.ociErr(w, http.StatusBadRequest, codeDigestInvalid, "invalid digest", digest)
		return
	}
	if id == "" {
		up, err := s.Store.NewUpload()
		if err != nil {
			s.ociErr(w, http.StatusInternalServerError, codeBlobUploadInvalid, "failed to start upload", nil)
			return
		}
		id = up.ID
	}
	// A PUT may carry a final chunk; an empty body simply appends nothing.
	if body != nil {
		if _, err := s.Store.Append(id, body, expectedOffset); err != nil {
			s.uploadError(w, err, id)
			return
		}
	}
	rs := s.Store.For(repo.Name)
	size, err := rs.Commit(id, digest)
	if err != nil {
		s.uploadError(w, err, id)
		return
	}
	// Record where the bytes actually went. When a rule is added later, the
	// difference between this and what the rules now say is what tells an
	// operator the repository needs migrating rather than leaving them to
	// discover it from a 404.
	placed := rs.BackendName()
	s.DB.RecordRepoStorage(r.Context(), repo.ID, placed)
	s.Store.Router().SetPlacement(repo.Name, placed)
	// Enforce the quota after the bytes have landed but before the blob is
	// linked, so an over-quota push is rejected without the repository being
	// charged for it. The orphaned blob is reclaimed by garbage collection.
	if repo.QuotaBytes > 0 {
		used, err := s.DB.RepositorySize(r.Context(), repo.ID)
		if err == nil && used+size > repo.QuotaBytes {
			s.ociErr(w, http.StatusRequestEntityTooLarge, codeDenied,
				fmt.Sprintf("repository quota exceeded: %d bytes used of %d, this blob adds %d",
					used, repo.QuotaBytes, size), nil)
			return
		}
	}
	if err := s.DB.LinkBlob(r.Context(), repo.ID, digest, size); err != nil {
		s.ociErr(w, http.StatusInternalServerError, codeUnsupported, "failed to record blob", nil)
		return
	}
	s.DB.TouchRepository(r.Context(), repo.ID)
	s.audit(r, "push.blob", name, digest, strconv.FormatInt(size, 10)+" bytes")

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) uploadError(w http.ResponseWriter, err error, id string) {
	switch {
	case errors.Is(err, store.ErrUploadClosed):
		s.ociErr(w, http.StatusNotFound, codeBlobUploadUnknown, "upload unknown", id)
	case errors.Is(err, store.ErrBadOffset):
		s.ociErr(w, http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid,
			"chunk does not start at the current upload offset", nil)
	case errors.Is(err, store.ErrBadDigest):
		s.ociErr(w, http.StatusBadRequest, codeDigestInvalid, err.Error(), nil)
	case errors.Is(err, store.ErrTooLarge):
		s.ociErr(w, http.StatusRequestEntityTooLarge, codeSizeInvalid, "blob exceeds the configured maximum size", nil)
	default:
		s.Log.Error("upload failed", "upload", id, "err", err)
		s.ociErr(w, http.StatusInternalServerError, codeBlobUploadInvalid, "upload failed", nil)
	}
}

// rangeHeader renders the inclusive byte range the registry currently holds.
func rangeHeader(offset int64) string {
	if offset == 0 {
		return "0-0"
	}
	return "0-" + strconv.FormatInt(offset-1, 10)
}

// parseContentRange reads a "start-end" chunk range as sent on PATCH.
func parseContentRange(v string) (start, end int64, err error) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "bytes ")
	if i := strings.IndexByte(v, '/'); i >= 0 {
		v = v[:i]
	}
	a, b, ok := strings.Cut(v, "-")
	if !ok {
		return 0, 0, fmt.Errorf("malformed Content-Range %q", v)
	}
	if start, err = strconv.ParseInt(strings.TrimSpace(a), 10, 64); err != nil {
		return 0, 0, fmt.Errorf("malformed Content-Range start")
	}
	if end, err = strconv.ParseInt(strings.TrimSpace(b), 10, 64); err != nil {
		return 0, 0, fmt.Errorf("malformed Content-Range end")
	}
	if start < 0 || end < start {
		return 0, 0, fmt.Errorf("invalid Content-Range bounds")
	}
	return start, end, nil
}
