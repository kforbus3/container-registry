package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/store"
)

// Pull-through caching. A repository under the proxy prefix that is missing
// locally is fetched from the upstream, stored, and then served from here
// forever after. The point is rate limits: a build farm becomes one puller
// rather than hundreds.

// cacheManifest fetches a manifest from the upstream and stores it, along with
// every blob it references. It reports whether the manifest is now local.
func (s *Server) cacheManifest(ctx context.Context, localRepo, upstreamRepo, reference string) (bool, error) {
	accept := []string{
		MediaTypeOCIManifest, MediaTypeOCIIndex,
		MediaTypeDockerManifest, MediaTypeDockerManifestList,
	}
	body, mediaType, _, err := s.upstream.Manifest(ctx, upstreamRepo, reference, accept)
	if err != nil {
		return false, err
	}
	parsed, err := parseManifest(body, mediaType)
	if err != nil {
		return false, fmt.Errorf("upstream manifest is not usable: %w", err)
	}
	repo, err := s.DB.EnsureRepository(ctx, localRepo)
	if err != nil {
		return false, err
	}

	// Children first: a manifest is only valid once everything it names is
	// present, which is the same rule applied to a push.
	for _, ref := range parsed.Refs {
		switch ref.Kind {
		case "foreign":
			continue
		case "manifest":
			if _, err := s.DB.GetManifest(ctx, repo.ID, ref.Digest); err == nil {
				continue
			}
			if _, err := s.cacheManifest(ctx, localRepo, upstreamRepo, ref.Digest); err != nil {
				return false, err
			}
		default:
			if err := s.cacheBlob(ctx, repo, upstreamRepo, ref.Digest); err != nil {
				return false, err
			}
		}
	}

	digest := store.Digest(body)
	if _, err := s.Store.PutBytes(body); err != nil {
		return false, err
	}
	m := &db.Manifest{
		RepoID: repo.ID, Digest: digest, MediaType: parsed.MediaType,
		ArtifactType: parsed.ArtifactType, Subject: parsed.Subject,
		Size: int64(len(body)), ConfigDigest: parsed.ConfigDigest,
	}
	if err := s.DB.PutManifest(ctx, m, parsed.Refs); err != nil {
		return false, err
	}
	s.DB.LinkBlob(ctx, repo.ID, digest, int64(len(body)))

	// Only a tag reference creates a tag; a digest reference is content that
	// happens to have been fetched by name.
	if !store.ValidDigest(reference) && validTag(reference) {
		if err := s.DB.PutTag(ctx, repo.ID, reference, digest); err != nil {
			return false, err
		}
	}
	s.Log.Info("cached upstream manifest",
		"repository", localRepo, "upstream", upstreamRepo, "reference", reference)
	return true, nil
}

// cacheBlob copies one blob from the upstream if it is not already stored.
func (s *Server) cacheBlob(ctx context.Context, repo *db.Repository, upstreamRepo, digest string) error {
	if _, linked, err := s.DB.BlobLinked(ctx, repo.ID, digest); err == nil && linked {
		return nil
	}
	// The content store is shared, so a blob already present from another
	// repository only needs linking rather than downloading again.
	if s.Store.Exists(digest) {
		size, _, err := s.Store.Stat(digest)
		if err == nil {
			return s.DB.LinkBlob(ctx, repo.ID, digest, size)
		}
	}

	rc, _, err := s.upstream.Blob(ctx, upstreamRepo, digest)
	if err != nil {
		return err
	}
	defer rc.Close()

	// Stream through the normal upload path so the digest is verified exactly
	// as it would be for a push: an upstream is not more trusted than a client.
	up, err := s.Store.NewUpload()
	if err != nil {
		return err
	}
	if _, err := s.Store.Append(up.ID, rc, -1); err != nil {
		s.Store.Cancel(up.ID)
		return err
	}
	size, err := s.Store.Commit(up.ID, digest)
	if err != nil {
		return fmt.Errorf("upstream blob %s failed verification: %w", digest, err)
	}
	return s.DB.LinkBlob(ctx, repo.ID, digest, size)
}

// tryCacheManifest attempts a cache fill for a manifest read, reporting whether
// the content is now available locally. Failures are logged and swallowed: a
// broken upstream should surface as "not found here", not as a 500.
func (s *Server) tryCacheManifest(r *http.Request, localRepo, reference string) bool {
	upstreamRepo, ok := s.proxyRepo(localRepo)
	if !ok {
		return false
	}
	cached, err := s.cacheManifest(r.Context(), localRepo, upstreamRepo, reference)
	if err != nil {
		s.Log.Warn("upstream fetch failed",
			"repository", localRepo, "reference", reference, "err", err)
		return false
	}
	return cached
}

// tryCacheBlob attempts a cache fill for a blob read.
func (s *Server) tryCacheBlob(r *http.Request, localRepo, digest string) bool {
	upstreamRepo, ok := s.proxyRepo(localRepo)
	if !ok {
		return false
	}
	repo, err := s.DB.EnsureRepository(r.Context(), localRepo)
	if err != nil {
		return false
	}
	if err := s.cacheBlob(r.Context(), repo, upstreamRepo, digest); err != nil {
		s.Log.Warn("upstream blob fetch failed",
			"repository", localRepo, "digest", digest, "err", err)
		return false
	}
	return true
}

var _ = io.Discard
var _ = strings.TrimSpace
