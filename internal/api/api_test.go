package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/kforbus3/container-registry/internal/auth"
	"github.com/kforbus3/container-registry/internal/config"
	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/gc"
	"github.com/kforbus3/container-registry/internal/store"
)

// ---------------------------------------------------------------- harness

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	db     *db.DB
	store  *store.Store
	gc     *gc.Collector
	server *Server
}

const adminPass = "adminpassword"

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()

	database, err := db.Open(filepath.Join(dir, "registry.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	st, err := store.New(filepath.Join(dir, "data"), 0)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	cfg := &config.Config{
		Realm: "test", DataDir: dir, SessionTTL: time.Hour,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewServer(cfg, database, st, log)
	collector := gc.New(database, st, log)
	collector.Grace = 0 // no grace period, so sweeps are deterministic in tests
	s.SetCollector(collector)

	hash, _ := auth.HashPassword(adminPass)
	if _, err := database.CreateUser(context.Background(), "admin", hash, "admin"); err != nil {
		t.Fatalf("create admin: %v", err)
	}

	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &harness{t: t, srv: ts, db: database, store: st, gc: collector, server: s}
}

// do issues a request as the admin unless creds are overridden.
func (h *harness) do(method, path string, body []byte, opts ...func(*http.Request)) *http.Response {
	h.t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, r)
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	req.SetBasicAuth("admin", adminPass)
	for _, o := range opts {
		o(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func asUser(user, pass string) func(*http.Request) {
	return func(r *http.Request) { r.SetBasicAuth(user, pass) }
}

func anonymous() func(*http.Request) {
	return func(r *http.Request) { r.Header.Del("Authorization") }
}

func contentType(ct string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Content-Type", ct) }
}

func (h *harness) expectStatus(resp *http.Response, want int, context string) []byte {
	h.t.Helper()
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != want {
		h.t.Fatalf("%s: status = %d, want %d; body = %s", context, resp.StatusCode, want, body)
	}
	return body
}

// pushBlob uploads content through the two-step upload flow and returns its digest.
func (h *harness) pushBlob(repo string, content []byte, opts ...func(*http.Request)) string {
	h.t.Helper()
	digest := store.Digest(content)

	resp := h.do(http.MethodPost, "/v2/"+repo+"/blobs/uploads/", nil, opts...)
	h.expectStatus(resp, http.StatusAccepted, "start upload")
	location := resp.Header.Get("Location")
	if location == "" {
		h.t.Fatal("start upload: no Location header")
	}

	resp = h.do(http.MethodPut, location+"?digest="+digest, content, opts...)
	h.expectStatus(resp, http.StatusCreated, "complete upload")
	if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
		h.t.Fatalf("Docker-Content-Digest = %q, want %q", got, digest)
	}
	return digest
}

// pushImage pushes a minimal but valid OCI image and returns the manifest digest.
func (h *harness) pushImage(repo, tag string, layers ...string) string {
	h.t.Helper()
	if len(layers) == 0 {
		layers = []string{"layer-" + repo + "-" + tag}
	}
	configJSON := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	configDigest := h.pushBlob(repo, configJSON)

	descs := make([]descriptor, 0, len(layers))
	for _, l := range layers {
		content := []byte(l)
		descs = append(descs, descriptor{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Digest:    h.pushBlob(repo, content),
			Size:      int64(len(content)),
		})
	}

	manifest, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config: &descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configJSON)),
		},
		Layers: descs,
	})

	resp := h.do(http.MethodPut, "/v2/"+repo+"/manifests/"+tag, manifest, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusCreated, "put manifest")
	return store.Digest(manifest)
}

func (h *harness) mustJSON(resp *http.Response, want int, v any) {
	h.t.Helper()
	body := h.expectStatus(resp, want, "decode json")
	if err := json.Unmarshal(body, v); err != nil {
		h.t.Fatalf("unmarshal %s: %v", body, err)
	}
}

// ---------------------------------------------------------------- tests

func TestVersionCheckRequiresAuth(t *testing.T) {
	h := newHarness(t)

	resp := h.do(http.MethodGet, "/v2/", nil, anonymous())
	h.expectStatus(resp, http.StatusUnauthorized, "anonymous /v2/")
	// The Basic challenge is what makes `docker login` prompt for credentials.
	if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="test"` {
		t.Fatalf("WWW-Authenticate = %q, want a Basic challenge", got)
	}

	resp = h.do(http.MethodGet, "/v2/", nil)
	h.expectStatus(resp, http.StatusOK, "authenticated /v2/")
	if got := resp.Header.Get("Docker-Distribution-API-Version"); got != "registry/2.0" {
		t.Errorf("API version header = %q", got)
	}
}

func TestFullPushPullCycle(t *testing.T) {
	h := newHarness(t)
	digest := h.pushImage("team-a/app", "v1")

	// Tag listing.
	var tags struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	h.mustJSON(h.do(http.MethodGet, "/v2/team-a/app/tags/list", nil), http.StatusOK, &tags)
	if len(tags.Tags) != 1 || tags.Tags[0] != "v1" {
		t.Fatalf("tags = %v, want [v1]", tags.Tags)
	}

	// Catalog.
	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	h.mustJSON(h.do(http.MethodGet, "/v2/_catalog", nil), http.StatusOK, &catalog)
	if len(catalog.Repositories) != 1 || catalog.Repositories[0] != "team-a/app" {
		t.Fatalf("catalog = %v", catalog.Repositories)
	}

	// GET by tag and by digest must agree.
	byTag := h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil)
	tagBody := h.expectStatus(byTag, http.StatusOK, "get manifest by tag")
	if got := byTag.Header.Get("Docker-Content-Digest"); got != digest {
		t.Fatalf("digest header = %q, want %q", got, digest)
	}
	byDigest := h.do(http.MethodGet, "/v2/team-a/app/manifests/"+digest, nil)
	digestBody := h.expectStatus(byDigest, http.StatusOK, "get manifest by digest")
	if !bytes.Equal(tagBody, digestBody) {
		t.Fatal("manifest fetched by tag differs from the one fetched by digest")
	}

	// HEAD is what a client uses to check existence before pushing.
	resp := h.do(http.MethodHead, "/v2/team-a/app/manifests/v1", nil)
	h.expectStatus(resp, http.StatusOK, "head manifest")
}

func TestBlobRoundTripAndRange(t *testing.T) {
	h := newHarness(t)
	content := []byte("0123456789abcdefghij")
	digest := h.pushBlob("team-a/app", content)

	resp := h.do(http.MethodGet, "/v2/team-a/app/blobs/"+digest, nil)
	got := h.expectStatus(resp, http.StatusOK, "get blob")
	if !bytes.Equal(got, content) {
		t.Fatalf("blob = %q, want %q", got, content)
	}

	// Range support matters for resumable pulls.
	resp = h.do(http.MethodGet, "/v2/team-a/app/blobs/"+digest, nil, func(r *http.Request) {
		r.Header.Set("Range", "bytes=5-9")
	})
	part := h.expectStatus(resp, http.StatusPartialContent, "ranged get")
	if string(part) != "56789" {
		t.Fatalf("ranged blob = %q, want %q", part, "56789")
	}
}

func TestChunkedUpload(t *testing.T) {
	h := newHarness(t)
	content := []byte("chunk-one|chunk-two|chunk-three")
	digest := store.Digest(content)

	resp := h.do(http.MethodPost, "/v2/team-a/chunked/blobs/uploads/", nil)
	h.expectStatus(resp, http.StatusAccepted, "start")
	location := resp.Header.Get("Location")

	offset := 0
	for _, chunk := range []string{"chunk-one|", "chunk-two|", "chunk-three"} {
		start := offset
		offset += len(chunk)
		resp = h.do(http.MethodPatch, location, []byte(chunk), func(r *http.Request) {
			r.Header.Set("Content-Range", fmt.Sprintf("%d-%d", start, offset-1))
		})
		h.expectStatus(resp, http.StatusAccepted, "patch chunk")
		if want := fmt.Sprintf("0-%d", offset-1); resp.Header.Get("Range") != want {
			t.Fatalf("Range = %q, want %q", resp.Header.Get("Range"), want)
		}
	}

	resp = h.do(http.MethodPut, location+"?digest="+digest, nil)
	h.expectStatus(resp, http.StatusCreated, "finalise")

	resp = h.do(http.MethodGet, "/v2/team-a/chunked/blobs/"+digest, nil)
	if got := h.expectStatus(resp, http.StatusOK, "fetch"); !bytes.Equal(got, content) {
		t.Fatalf("reassembled blob = %q, want %q", got, content)
	}
}

func TestMonolithicUpload(t *testing.T) {
	h := newHarness(t)
	content := []byte("single-request upload")
	digest := store.Digest(content)

	resp := h.do(http.MethodPost, "/v2/team-a/mono/blobs/uploads/?digest="+digest, content)
	h.expectStatus(resp, http.StatusCreated, "monolithic upload")

	resp = h.do(http.MethodHead, "/v2/team-a/mono/blobs/"+digest, nil)
	h.expectStatus(resp, http.StatusOK, "head blob")
}

func TestUploadRejectsCorruptedContent(t *testing.T) {
	h := newHarness(t)
	// Claim a digest that does not match the bytes sent.
	wrongDigest := store.Digest([]byte("what the client claims"))

	resp := h.do(http.MethodPost, "/v2/team-a/app/blobs/uploads/", nil)
	h.expectStatus(resp, http.StatusAccepted, "start")
	location := resp.Header.Get("Location")

	resp = h.do(http.MethodPut, location+"?digest="+wrongDigest, []byte("what was actually sent"))
	h.expectStatus(resp, http.StatusBadRequest, "corrupted upload must be rejected")

	if h.store.Exists(wrongDigest) {
		t.Fatal("a blob was stored under a digest that does not match its content")
	}
}

func TestManifestRejectsMissingBlobs(t *testing.T) {
	h := newHarness(t)
	// A manifest referencing a layer that was never uploaded.
	manifest, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        &descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: store.Digest([]byte("nope")), Size: 4},
		Layers:        []descriptor{{Digest: store.Digest([]byte("also nope")), Size: 9}},
	})
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/v1", manifest, contentType(MediaTypeOCIManifest))
	body := h.expectStatus(resp, http.StatusNotFound, "manifest with missing blobs")
	if !bytes.Contains(body, []byte(codeManifestBlobUnknown)) {
		t.Fatalf("error code should be %s, got %s", codeManifestBlobUnknown, body)
	}
}

func TestManifestDigestMismatchRejected(t *testing.T) {
	h := newHarness(t)
	h.pushImage("team-a/app", "v1")

	body := []byte(`{"schemaVersion":2,"mediaType":"` + MediaTypeOCIIndex + `","manifests":[]}`)
	wrong := store.Digest([]byte("something else"))
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/"+wrong, body, contentType(MediaTypeOCIIndex))
	h.expectStatus(resp, http.StatusBadRequest, "digest reference must match content")
}

func TestSchema1ManifestRejected(t *testing.T) {
	h := newHarness(t)
	body := []byte(`{"schemaVersion":1,"name":"x","tag":"v1","fsLayers":[]}`)
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/v1", body, contentType(MediaTypeDockerManifestV1))
	h.expectStatus(resp, http.StatusBadRequest, "schema 1 must be rejected")
}

func TestManifestIndex(t *testing.T) {
	h := newHarness(t)
	amd := h.pushImage("team-a/multi", "sha-amd64")
	arm := h.pushImage("team-a/multi", "sha-arm64", "arm-layer")

	index, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIIndex,
		Manifests: []descriptor{
			{MediaType: MediaTypeOCIManifest, Digest: amd, Size: 100, Platform: &platform{OS: "linux", Architecture: "amd64"}},
			{MediaType: MediaTypeOCIManifest, Digest: arm, Size: 100, Platform: &platform{OS: "linux", Architecture: "arm64"}},
		},
	})
	resp := h.do(http.MethodPut, "/v2/team-a/multi/manifests/latest", index, contentType(MediaTypeOCIIndex))
	h.expectStatus(resp, http.StatusCreated, "put index")

	resp = h.do(http.MethodGet, "/v2/team-a/multi/manifests/latest", nil)
	got := h.expectStatus(resp, http.StatusOK, "get index")
	if !bytes.Equal(got, index) {
		t.Fatal("index does not round-trip byte-for-byte")
	}

	// An index naming a child that was never pushed must be refused.
	bad, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2, MediaType: MediaTypeOCIIndex,
		Manifests: []descriptor{{Digest: store.Digest([]byte("ghost")), Size: 1}},
	})
	resp = h.do(http.MethodPut, "/v2/team-a/multi/manifests/broken", bad, contentType(MediaTypeOCIIndex))
	h.expectStatus(resp, http.StatusNotFound, "index with a missing child")
}

func TestCrossRepositoryMount(t *testing.T) {
	h := newHarness(t)
	content := []byte("shared base layer")
	digest := h.pushBlob("team-a/source", content)

	resp := h.do(http.MethodPost,
		"/v2/team-a/target/blobs/uploads/?mount="+digest+"&from=team-a/source", nil)
	h.expectStatus(resp, http.StatusCreated, "mount")
	if got := resp.Header.Get("Docker-Content-Digest"); got != digest {
		t.Fatalf("mount digest = %q, want %q", got, digest)
	}

	// The blob is now servable from the target repository without re-uploading.
	resp = h.do(http.MethodGet, "/v2/team-a/target/blobs/"+digest, nil)
	if got := h.expectStatus(resp, http.StatusOK, "get mounted blob"); !bytes.Equal(got, content) {
		t.Fatal("mounted blob content differs")
	}
	// And exactly one copy exists on disk.
	if _, count, _ := h.store.DiskUsage(); count != 1 {
		t.Fatalf("disk holds %d blobs, want 1", count)
	}
}

func TestBlobIsolationBetweenRepositories(t *testing.T) {
	h := newHarness(t)
	digest := h.pushBlob("team-a/private", []byte("secret layer"))

	// Another repository must not serve a blob it never mounted, even though
	// the bytes exist in the shared content store.
	h.do(http.MethodPost, "/v2/team-b/other/blobs/uploads/", nil).Body.Close()
	resp := h.do(http.MethodGet, "/v2/team-b/other/blobs/"+digest, nil)
	h.expectStatus(resp, http.StatusNotFound, "unlinked blob must not be served")
}

func TestTokenScopeEnforcement(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("userpassword")
	u, _ := h.db.CreateUser(ctx, "dev", hash, "user")

	plaintext, prefix, secretHash, _ := auth.GenerateToken()
	h.db.CreateToken(ctx, &db.Token{
		Name: "scoped", UserID: u.ID, Prefix: prefix, SecretHash: secretHash,
		CanPull: true, CanPush: true, RepoPattern: "team-a/*",
	})
	withToken := func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+plaintext)
	}

	// In scope: allowed.
	resp := h.do(http.MethodPost, "/v2/team-a/app/blobs/uploads/", nil, withToken)
	h.expectStatus(resp, http.StatusAccepted, "push within scope")

	// Out of scope: denied.
	resp = h.do(http.MethodPost, "/v2/team-b/app/blobs/uploads/", nil, withToken)
	h.expectStatus(resp, http.StatusForbidden, "push outside scope")

	// Delete was never granted, even inside the scope.
	h.pushImage("team-a/app", "v1")
	resp = h.do(http.MethodDelete, "/v2/team-a/app/manifests/v1", nil, withToken)
	h.expectStatus(resp, http.StatusForbidden, "delete without the delete permission")
}

func TestPullOnlyTokenCannotPush(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("userpassword")
	u, _ := h.db.CreateUser(ctx, "reader", hash, "user")

	plaintext, prefix, secretHash, _ := auth.GenerateToken()
	h.db.CreateToken(ctx, &db.Token{
		Name: "readonly", UserID: u.ID, Prefix: prefix, SecretHash: secretHash,
		CanPull: true, RepoPattern: "*",
	})
	withToken := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+plaintext) }

	h.pushImage("team-a/app", "v1")

	resp := h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil, withToken)
	h.expectStatus(resp, http.StatusOK, "pull with a read-only token")

	resp = h.do(http.MethodPost, "/v2/team-a/app/blobs/uploads/", nil, withToken)
	h.expectStatus(resp, http.StatusForbidden, "push with a read-only token")
}

func TestCatalogHidesRepositoriesOutOfScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.pushImage("team-a/app", "v1")
	h.pushImage("team-b/app", "v1")

	hash, _ := auth.HashPassword("userpassword")
	u, _ := h.db.CreateUser(ctx, "dev", hash, "user")
	plaintext, prefix, secretHash, _ := auth.GenerateToken()
	h.db.CreateToken(ctx, &db.Token{
		Name: "scoped", UserID: u.ID, Prefix: prefix, SecretHash: secretHash,
		CanPull: true, RepoPattern: "team-a/*",
	})

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	h.mustJSON(h.do(http.MethodGet, "/v2/_catalog", nil, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+plaintext)
	}), http.StatusOK, &catalog)

	if len(catalog.Repositories) != 1 || catalog.Repositories[0] != "team-a/app" {
		t.Fatalf("catalog leaked out-of-scope repositories: %v", catalog.Repositories)
	}
}

func TestDeleteTagKeepsManifest(t *testing.T) {
	h := newHarness(t)
	digest := h.pushImage("team-a/app", "v1")
	h.do(http.MethodPut, "/v2/team-a/app/manifests/v2", mustManifestBytes(h, "team-a/app", digest), contentType(MediaTypeOCIManifest)).Body.Close()

	resp := h.do(http.MethodDelete, "/v2/team-a/app/manifests/v1", nil)
	h.expectStatus(resp, http.StatusAccepted, "delete tag")

	// The tag is gone...
	resp = h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil)
	h.expectStatus(resp, http.StatusNotFound, "deleted tag")

	// ...but the manifest is still addressable by digest.
	resp = h.do(http.MethodGet, "/v2/team-a/app/manifests/"+digest, nil)
	h.expectStatus(resp, http.StatusOK, "manifest by digest after tag delete")
}

// mustManifestBytes re-reads a stored manifest so a second tag can be pushed
// pointing at the same content.
func mustManifestBytes(h *harness, repo, digest string) []byte {
	h.t.Helper()
	b, err := h.store.ReadAll(digest)
	if err != nil {
		h.t.Fatalf("read manifest: %v", err)
	}
	return b
}

func TestDeleteManifestByDigestRemovesTags(t *testing.T) {
	h := newHarness(t)
	digest := h.pushImage("team-a/app", "v1")

	resp := h.do(http.MethodDelete, "/v2/team-a/app/manifests/"+digest, nil)
	h.expectStatus(resp, http.StatusAccepted, "delete manifest")

	resp = h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil)
	h.expectStatus(resp, http.StatusNotFound, "tag should follow its manifest")
}

func TestImmutableRepositoryBlocksTagReassignment(t *testing.T) {
	h := newHarness(t)
	h.pushImage("team-a/app", "v1")

	repo, _ := h.db.GetRepository(context.Background(), "team-a/app")
	if err := h.db.UpdateRepository(context.Background(), repo.ID, false, true, ""); err != nil {
		t.Fatalf("mark immutable: %v", err)
	}

	// Re-pushing identical content under the same tag is a no-op and allowed.
	digest := h.pushImage("team-a/app", "v1")
	_ = digest

	// Moving the tag to different content must be refused.
	other := h.pushImage("team-a/app", "temp", "a-completely-different-layer")
	body := mustManifestBytes(h, "team-a/app", other)
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/v1", body, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusConflict, "immutable tag reassignment")
}

func TestReferrersAPI(t *testing.T) {
	h := newHarness(t)
	subject := h.pushImage("team-a/app", "v1")

	// A signature-style artifact attached to the image.
	configJSON := []byte(`{}`)
	configDigest := h.pushBlob("team-a/app", configJSON)
	sig := []byte("signature-bytes")
	sigDigest := h.pushBlob("team-a/app", sig)

	artifact, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		ArtifactType:  "application/vnd.example.signature.v1+json",
		Config:        &descriptor{MediaType: MediaTypeOCIEmptyJSON, Digest: configDigest, Size: int64(len(configJSON))},
		Layers:        []descriptor{{MediaType: "application/octet-stream", Digest: sigDigest, Size: int64(len(sig))}},
		Subject:       &descriptor{MediaType: MediaTypeOCIManifest, Digest: subject, Size: 100},
	})
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/"+store.Digest(artifact), artifact, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusCreated, "push artifact")
	if got := resp.Header.Get("OCI-Subject"); got != subject {
		t.Errorf("OCI-Subject = %q, want %q", got, subject)
	}

	var idx referrersIndex
	h.mustJSON(h.do(http.MethodGet, "/v2/team-a/app/referrers/"+subject, nil), http.StatusOK, &idx)
	if len(idx.Manifests) != 1 {
		t.Fatalf("referrers = %d, want 1", len(idx.Manifests))
	}
	if idx.Manifests[0].ArtifactType != "application/vnd.example.signature.v1+json" {
		t.Errorf("artifactType = %q", idx.Manifests[0].ArtifactType)
	}

	// Filtering by a non-matching artifactType returns an empty index.
	h.mustJSON(h.do(http.MethodGet, "/v2/team-a/app/referrers/"+subject+"?artifactType=application/vnd.other", nil),
		http.StatusOK, &idx)
	if len(idx.Manifests) != 0 {
		t.Fatalf("filtered referrers = %d, want 0", len(idx.Manifests))
	}
}

func TestInvalidRepositoryNamesRejected(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"UPPERCASE", "has spaces", "-leading", "trailing-", "double//slash"} {
		resp := h.do(http.MethodGet, "/v2/"+name+"/tags/list", nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
			t.Errorf("repo %q: status = %d, want 400 or 404; body = %s", name, resp.StatusCode, body)
		}
	}
}

func TestGarbageCollection(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.pushImage("team-a/keep", "v1", "kept-layer")
	digest := h.pushImage("team-a/drop", "v1", "dropped-layer")

	_, before, _ := h.store.DiskUsage()

	// Remove the manifest so its layers become unreferenced.
	resp := h.do(http.MethodDelete, "/v2/team-a/drop/manifests/"+digest, nil)
	h.expectStatus(resp, http.StatusAccepted, "delete manifest")

	res, err := h.gc.Run(ctx, false)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if res.BlobsDeleted == 0 {
		t.Fatal("garbage collection reclaimed nothing after a manifest delete")
	}

	_, after, _ := h.store.DiskUsage()
	if after >= before {
		t.Fatalf("blob count did not shrink: %d -> %d", before, after)
	}
	// The surviving image must still be fully pullable.
	resp = h.do(http.MethodGet, "/v2/team-a/keep/manifests/v1", nil)
	h.expectStatus(resp, http.StatusOK, "kept image after gc")
}

func TestGarbageCollectionKeepsSharedLayers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Two repositories referencing the same layer content.
	shared := "shared-layer-content"
	h.pushImage("team-a/one", "v1", shared)
	digest := h.pushImage("team-a/two", "v1", shared)

	resp := h.do(http.MethodDelete, "/v2/team-a/two/manifests/"+digest, nil)
	h.expectStatus(resp, http.StatusAccepted, "delete one of them")

	if _, err := h.gc.Run(ctx, false); err != nil {
		t.Fatalf("gc: %v", err)
	}
	// The shared layer must survive because team-a/one still needs it.
	resp = h.do(http.MethodGet, "/v2/team-a/one/manifests/v1", nil)
	h.expectStatus(resp, http.StatusOK, "surviving manifest")

	sharedDigest := store.Digest([]byte(shared))
	if !h.store.Exists(sharedDigest) {
		t.Fatal("garbage collection deleted a layer another repository still references")
	}
}

func TestGarbageCollectionDryRunDeletesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	digest := h.pushImage("team-a/app", "v1")
	h.do(http.MethodDelete, "/v2/team-a/app/manifests/"+digest, nil).Body.Close()

	_, before, _ := h.store.DiskUsage()
	res, err := h.gc.Run(ctx, true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	_, after, _ := h.store.DiskUsage()
	if before != after {
		t.Fatalf("dry run removed blobs: %d -> %d", before, after)
	}
	if res.BlobsDeleted == 0 {
		t.Fatal("dry run should still report what it would delete")
	}
}

// ---------------------------------------------------------------- admin API

func TestAdminTagCreation(t *testing.T) {
	h := newHarness(t)
	digest := h.pushImage("team-a/app", "v1")

	body, _ := json.Marshal(map[string]string{"tag": "stable", "target": "v1"})
	resp := h.do(http.MethodPost, "/api/repositories/team-a/app/tags", body)
	var created struct {
		Tag    string `json:"tag"`
		Digest string `json:"digest"`
	}
	h.mustJSON(resp, http.StatusCreated, &created)
	if created.Digest != digest {
		t.Fatalf("new tag points at %s, want %s", created.Digest, digest)
	}

	// The new tag must be visible through the OCI API too.
	var tags struct {
		Tags []string `json:"tags"`
	}
	h.mustJSON(h.do(http.MethodGet, "/v2/team-a/app/tags/list", nil), http.StatusOK, &tags)
	if len(tags.Tags) != 2 {
		t.Fatalf("tags = %v, want two entries", tags.Tags)
	}

	// Tagging a manifest that does not exist must fail.
	body, _ = json.Marshal(map[string]string{"tag": "ghost", "target": store.Digest([]byte("nope"))})
	resp = h.do(http.MethodPost, "/api/repositories/team-a/app/tags", body)
	h.expectStatus(resp, http.StatusNotFound, "tagging a missing manifest")
}

func TestAdminAPIRequiresAuth(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/api/stats", "/api/repositories", "/api/tokens", "/api/users"} {
		resp := h.do(http.MethodGet, path, nil, anonymous())
		h.expectStatus(resp, http.StatusUnauthorized, "anonymous "+path)
	}
}

func TestNonAdminCannotReachAdminEndpoints(t *testing.T) {
	h := newHarness(t)
	hash, _ := auth.HashPassword("userpassword")
	h.db.CreateUser(context.Background(), "dev", hash, "user")

	for _, path := range []string{"/api/users", "/api/gc", "/api/settings", "/api/audit"} {
		resp := h.do(http.MethodGet, path, nil, asUser("dev", "userpassword"))
		h.expectStatus(resp, http.StatusForbidden, "non-admin "+path)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	h := newHarness(t)
	var users struct {
		Users []struct {
			ID   int64  `json:"id"`
			Name string `json:"username"`
		} `json:"users"`
	}
	h.mustJSON(h.do(http.MethodGet, "/api/users", nil), http.StatusOK, &users)
	if len(users.Users) != 1 {
		t.Fatalf("expected exactly one user, got %d", len(users.Users))
	}
	id := users.Users[0].ID

	body, _ := json.Marshal(map[string]any{"role": "user"})
	resp := h.do(http.MethodPatch, fmt.Sprintf("/api/users/%d", id), body)
	h.expectStatus(resp, http.StatusConflict, "demoting the last admin")

	body, _ = json.Marshal(map[string]any{"disabled": true})
	resp = h.do(http.MethodPatch, fmt.Sprintf("/api/users/%d", id), body)
	h.expectStatus(resp, http.StatusConflict, "disabling the last admin")
}

func TestTokenLifecycleThroughAPI(t *testing.T) {
	h := newHarness(t)

	body, _ := json.Marshal(map[string]any{
		"name": "ci", "can_pull": true, "can_push": true, "repo_pattern": "team-a/*",
	})
	var created struct {
		Secret string `json:"secret"`
		Token  struct {
			ID int64 `json:"id"`
		} `json:"token"`
	}
	h.mustJSON(h.do(http.MethodPost, "/api/tokens", body), http.StatusCreated, &created)
	if created.Secret == "" {
		t.Fatal("token creation did not return a secret")
	}

	withToken := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+created.Secret) }
	resp := h.do(http.MethodGet, "/v2/", nil, withToken)
	h.expectStatus(resp, http.StatusOK, "new token works")

	// After revocation it must stop working immediately.
	resp = h.do(http.MethodPost, fmt.Sprintf("/api/tokens/%d/revoke", created.Token.ID), nil)
	h.expectStatus(resp, http.StatusOK, "revoke")

	resp = h.do(http.MethodGet, "/v2/", nil, withToken)
	h.expectStatus(resp, http.StatusUnauthorized, "revoked token must be rejected")
}

func TestTokenCannotMintTokens(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("userpassword")
	u, _ := h.db.CreateUser(ctx, "dev", hash, "user")

	plaintext, prefix, secretHash, _ := auth.GenerateToken()
	h.db.CreateToken(ctx, &db.Token{
		Name: "ci", UserID: u.ID, Prefix: prefix, SecretHash: secretHash,
		CanPull: true, CanPush: true, RepoPattern: "*",
	})

	body, _ := json.Marshal(map[string]any{"name": "escalation", "can_pull": true})
	resp := h.do(http.MethodPost, "/api/tokens", body, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+plaintext)
	})
	h.expectStatus(resp, http.StatusForbidden, "a token minting another token")
}

func TestPublicRepositoryReadableByAnyUser(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.pushImage("team-a/app", "v1")

	hash, _ := auth.HashPassword("userpassword")
	u, _ := h.db.CreateUser(ctx, "outsider", hash, "user")
	plaintext, prefix, secretHash, _ := auth.GenerateToken()
	h.db.CreateToken(ctx, &db.Token{
		Name: "narrow", UserID: u.ID, Prefix: prefix, SecretHash: secretHash,
		CanPull: true, RepoPattern: "nothing/*",
	})
	withToken := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+plaintext) }

	// Out of scope while private.
	resp := h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil, withToken)
	h.expectStatus(resp, http.StatusForbidden, "private repo out of scope")

	repo, _ := h.db.GetRepository(ctx, "team-a/app")
	h.db.UpdateRepository(ctx, repo.ID, true, false, "")

	// Readable once public.
	resp = h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil, withToken)
	h.expectStatus(resp, http.StatusOK, "public repo")

	// But still not writable.
	resp = h.do(http.MethodPost, "/v2/team-a/app/blobs/uploads/", nil, withToken)
	h.expectStatus(resp, http.StatusForbidden, "public repo is not writable")
}

func TestAuditLogRecordsPushes(t *testing.T) {
	h := newHarness(t)
	h.pushImage("team-a/app", "v1")

	var audit struct {
		Entries []struct {
			Action string `json:"action"`
			Repo   string `json:"repo"`
		} `json:"entries"`
	}
	h.mustJSON(h.do(http.MethodGet, "/api/audit", nil), http.StatusOK, &audit)

	var sawTagPush bool
	for _, e := range audit.Entries {
		if e.Action == "push.tag" && e.Repo == "team-a/app" {
			sawTagPush = true
		}
	}
	if !sawTagPush {
		t.Fatalf("audit log has no push.tag entry: %+v", audit.Entries)
	}
}

func TestWebUIIsServed(t *testing.T) {
	h := newHarness(t)
	resp := h.do(http.MethodGet, "/", nil, anonymous())
	body := h.expectStatus(resp, http.StatusOK, "index")
	if !bytes.Contains(body, []byte("Container Registry")) {
		t.Fatal("index.html was not served")
	}
	// Client-side routes fall back to the SPA shell.
	resp = h.do(http.MethodGet, "/some/deep/route", nil, anonymous())
	h.expectStatus(resp, http.StatusOK, "SPA fallback")
}

// ------------------------------------------------- OCI spec conformance regressions
//
// Each test below pins a behaviour the official OCI distribution-spec
// conformance suite exercises, so a regression is caught by `go test` rather
// than only by the full suite.

// Clients commonly send one media type per Accept header line rather than a
// single comma-separated value. Reading only the first line made every
// manifest GET and HEAD fail against conformant clients.
func TestManifestAcceptSentAsRepeatedHeaders(t *testing.T) {
	h := newHarness(t)
	digest := h.pushImage("team-a/app", "v1")

	repeatedAccept := func(r *http.Request) {
		r.Header.Del("Accept")
		r.Header.Add("Accept", MediaTypeOCIIndex)    // not what is stored
		r.Header.Add("Accept", MediaTypeOCIManifest) // what is stored
	}
	resp := h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil, repeatedAccept)
	h.expectStatus(resp, http.StatusOK, "GET with repeated Accept headers")

	resp = h.do(http.MethodHead, "/v2/team-a/app/manifests/"+digest, nil, repeatedAccept)
	h.expectStatus(resp, http.StatusOK, "HEAD with repeated Accept headers")

	// A client that genuinely accepts nothing we hold still gets a 404.
	resp = h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil, func(r *http.Request) {
		r.Header.Set("Accept", "application/vnd.example.nothing")
	})
	h.expectStatus(resp, http.StatusNotFound, "GET with a non-matching Accept")

	// A wildcard accepts whatever is stored.
	resp = h.do(http.MethodGet, "/v2/team-a/app/manifests/v1", nil, func(r *http.Request) {
		r.Header.Set("Accept", "*/*")
	})
	h.expectStatus(resp, http.StatusOK, "GET with */*")
}

// The spec requires sha256 and permits sha512; the conformance suite exercises
// both across every upload style.
func TestSHA512BlobAndManifest(t *testing.T) {
	h := newHarness(t)
	content := []byte("a layer named with sha512")
	digest, err := store.DigestWith("sha512", content)
	if err != nil {
		t.Fatalf("DigestWith: %v", err)
	}

	resp := h.do(http.MethodPost, "/v2/team-a/s512/blobs/uploads/", nil)
	h.expectStatus(resp, http.StatusAccepted, "start upload")
	location := resp.Header.Get("Location")

	resp = h.do(http.MethodPut, location+"?digest="+digest, content)
	h.expectStatus(resp, http.StatusCreated, "finalise a sha512 blob")

	resp = h.do(http.MethodGet, "/v2/team-a/s512/blobs/"+digest, nil)
	if got := h.expectStatus(resp, http.StatusOK, "fetch"); !bytes.Equal(got, content) {
		t.Fatal("sha512 blob does not round-trip")
	}

	// And a manifest addressed by a sha512 digest.
	configJSON := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgDigest, _ := store.DigestWith("sha512", configJSON)
	resp = h.do(http.MethodPost, "/v2/team-a/s512/blobs/uploads/?digest="+cfgDigest, configJSON)
	h.expectStatus(resp, http.StatusCreated, "upload sha512 config")

	manifest, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config: &descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cfgDigest, Size: int64(len(configJSON)),
		},
		Layers: []descriptor{{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Digest:    digest, Size: int64(len(content)),
		}},
	})
	manifestDigest, _ := store.DigestWith("sha512", manifest)
	resp = h.do(http.MethodPut, "/v2/team-a/s512/manifests/"+manifestDigest, manifest,
		contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusCreated, "put a sha512-addressed manifest")

	resp = h.do(http.MethodGet, "/v2/team-a/s512/manifests/"+manifestDigest, nil)
	body := h.expectStatus(resp, http.StatusOK, "get it back")
	if !bytes.Equal(body, manifest) {
		t.Fatal("sha512-addressed manifest does not round-trip")
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != manifestDigest {
		t.Fatalf("content digest header = %q, want the sha512 digest", got)
	}
}

// "When n is zero, this endpoint MUST return an empty list, and MUST NOT
// include a Link header." An absent n means no limit, which is different.
func TestPaginationNZero(t *testing.T) {
	h := newHarness(t)
	h.pushImage("team-a/app", "a")
	h.pushImage("team-a/app", "b")
	h.pushImage("team-a/app", "c")

	var tags struct {
		Tags []string `json:"tags"`
	}
	resp := h.do(http.MethodGet, "/v2/team-a/app/tags/list?n=0", nil)
	h.mustJSON(resp, http.StatusOK, &tags)
	if len(tags.Tags) != 0 {
		t.Fatalf("n=0 returned %v, want an empty list", tags.Tags)
	}
	if link := resp.Header.Get("Link"); link != "" {
		t.Fatalf("n=0 must not carry a Link header, got %q", link)
	}

	// Absent n is not the same as n=0.
	h.mustJSON(h.do(http.MethodGet, "/v2/team-a/app/tags/list", nil), http.StatusOK, &tags)
	if len(tags.Tags) != 3 {
		t.Fatalf("absent n returned %v, want all three tags", tags.Tags)
	}

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	h.mustJSON(h.do(http.MethodGet, "/v2/_catalog?n=0", nil), http.StatusOK, &catalog)
	if len(catalog.Repositories) != 0 {
		t.Fatalf("catalog n=0 returned %v, want an empty list", catalog.Repositories)
	}
}

// The referrers API returns an empty index rather than an error when the
// subject has no referrers, including when the repository does not exist.
func TestReferrersEmptyIndexForUnknownRepository(t *testing.T) {
	h := newHarness(t)
	digest := store.Digest([]byte("nothing refers to this"))

	resp := h.do(http.MethodGet, "/v2/team-a/never-pushed/referrers/"+digest, nil)
	var idx referrersIndex
	h.mustJSON(resp, http.StatusOK, &idx)
	if got := resp.Header.Get("Content-Type"); got != MediaTypeOCIIndex {
		t.Fatalf("Content-Type = %q, want %q", got, MediaTypeOCIIndex)
	}
	if idx.MediaType != MediaTypeOCIIndex || idx.Manifests == nil || len(idx.Manifests) != 0 {
		t.Fatalf("want an empty OCI index, got %+v", idx)
	}
}

// A closing PUT may carry a final chunk, and an offset that does not continue
// the upload is a range error rather than a digest error.
func TestPutWithOutOfOrderContentRange(t *testing.T) {
	h := newHarness(t)
	resp := h.do(http.MethodPost, "/v2/team-a/oo/blobs/uploads/", nil)
	h.expectStatus(resp, http.StatusAccepted, "start")
	location := resp.Header.Get("Location")

	resp = h.do(http.MethodPatch, location, []byte("AAAAA"), func(r *http.Request) {
		r.Header.Set("Content-Range", "0-4")
	})
	h.expectStatus(resp, http.StatusAccepted, "first chunk")

	// PATCH out of order.
	resp = h.do(http.MethodPatch, location, []byte("BBBBB"), func(r *http.Request) {
		r.Header.Set("Content-Range", "50-54")
	})
	h.expectStatus(resp, http.StatusRequestedRangeNotSatisfiable, "out-of-order PATCH")

	// PUT out of order must also be a range error, not a digest error.
	resp = h.do(http.MethodPut, location+"?digest="+store.Digest([]byte("AAAAABBBBB")),
		[]byte("BBBBB"), func(r *http.Request) {
			r.Header.Set("Content-Range", "50-54")
		})
	h.expectStatus(resp, http.StatusRequestedRangeNotSatisfiable, "out-of-order PUT")
}

// Optional spec feature: pushing a manifest by digest may create tags via
// repeated `tag` query parameters, each echoed back in an OCI-Tag header.
func TestManifestTagQueryParameters(t *testing.T) {
	h := newHarness(t)
	digest := h.pushImage("team-a/app", "seed")
	body := mustManifestBytes(h, "team-a/app", digest)

	resp := h.do(http.MethodPut,
		"/v2/team-a/app/manifests/"+digest+"?tag=1.2.3&tag=1.2&tag=latest",
		body, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusCreated, "push by digest with tag params")
	if got := resp.Header.Get("OCI-Tag"); got == "" {
		t.Fatal("accepted tags must be echoed in an OCI-Tag header")
	}

	var tags struct {
		Tags []string `json:"tags"`
	}
	h.mustJSON(h.do(http.MethodGet, "/v2/team-a/app/tags/list", nil), http.StatusOK, &tags)
	for _, want := range []string{"1.2.3", "1.2", "latest"} {
		if !slices.Contains(tags.Tags, want) {
			t.Errorf("tag %q was not created; have %v", want, tags.Tags)
		}
	}

	// An invalid tag is rejected rather than silently skipped.
	resp = h.do(http.MethodPut, "/v2/team-a/app/manifests/"+digest+"?tag=not%20valid",
		body, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusBadRequest, "invalid tag parameter")
}

// OCI 1.1: a manifest with no artifactType takes its config media type, with
// no exemption for the standard image config. Referrers listings depend on it.
func TestArtifactTypeFallsBackToConfigMediaType(t *testing.T) {
	h := newHarness(t)
	subject := h.pushImage("team-a/app", "v1")

	configJSON := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgDigest := h.pushBlob("team-a/app", configJSON)

	// An ordinary image manifest — standard config type, no artifactType —
	// attached to the subject.
	referrer, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config: &descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cfgDigest, Size: int64(len(configJSON)),
		},
		Layers:  []descriptor{},
		Subject: &descriptor{MediaType: MediaTypeOCIManifest, Digest: subject, Size: 100},
	})
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/"+store.Digest(referrer),
		referrer, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusCreated, "push referrer")

	var idx referrersIndex
	h.mustJSON(h.do(http.MethodGet, "/v2/team-a/app/referrers/"+subject, nil), http.StatusOK, &idx)
	if len(idx.Manifests) != 1 {
		t.Fatalf("referrers = %d, want 1", len(idx.Manifests))
	}
	if got := idx.Manifests[0].ArtifactType; got != "application/vnd.oci.image.config.v1+json" {
		t.Fatalf("artifactType = %q, want it to fall back to the config media type", got)
	}
}

// A manifest may name a subject that has not been pushed yet: the spec requires
// the registry to accept it so a client can push in either order.
func TestManifestWithUnknownSubjectAccepted(t *testing.T) {
	h := newHarness(t)
	configJSON := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgDigest := h.pushBlob("team-a/app", configJSON)

	manifest, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config: &descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cfgDigest, Size: int64(len(configJSON)),
		},
		Layers:  []descriptor{},
		Subject: &descriptor{MediaType: MediaTypeOCIManifest, Digest: store.Digest([]byte("not pushed")), Size: 100},
	})
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/"+store.Digest(manifest),
		manifest, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusCreated, "manifest naming an absent subject")
}

// Cancelling an upload session releases it.
func TestUploadCancel(t *testing.T) {
	h := newHarness(t)
	resp := h.do(http.MethodPost, "/v2/team-a/cancel/blobs/uploads/", nil)
	h.expectStatus(resp, http.StatusAccepted, "start")
	location := resp.Header.Get("Location")

	resp = h.do(http.MethodPatch, location, []byte("partial"))
	h.expectStatus(resp, http.StatusAccepted, "chunk")

	resp = h.do(http.MethodDelete, location, nil)
	h.expectStatus(resp, http.StatusNoContent, "cancel")

	resp = h.do(http.MethodGet, location, nil)
	h.expectStatus(resp, http.StatusNotFound, "cancelled session must be gone")
}

// end-4c: a client may declare the digest algorithm when starting an upload.
func TestUploadDigestAlgorithmParameter(t *testing.T) {
	h := newHarness(t)

	for _, algo := range store.SupportedAlgorithms {
		resp := h.do(http.MethodPost, "/v2/team-a/algo/blobs/uploads/?digest-algorithm="+algo, nil)
		h.expectStatus(resp, http.StatusAccepted, "declared algorithm "+algo)
	}
	// An algorithm we cannot honour must fail before the client streams a layer.
	resp := h.do(http.MethodPost, "/v2/team-a/algo/blobs/uploads/?digest-algorithm=md5", nil)
	h.expectStatus(resp, http.StatusBadRequest, "unsupported declared algorithm")
}

// A tag normally points at an index — that is what `docker push` produces even
// for a single platform — and an index gets no SBOM of its own. Asking for the
// SBOM of the digest a user actually has in hand must therefore resolve through
// the index to the platform manifest beneath it.
func TestSBOMResolvesThroughIndex(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	child := h.pushImage("team-a/app", "sha-amd64")
	index, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIIndex,
		Manifests: []descriptor{{
			MediaType: MediaTypeOCIManifest, Digest: child, Size: 100,
			Platform: &platform{OS: "linux", Architecture: "amd64"},
		}},
	})
	resp := h.do(http.MethodPut, "/v2/team-a/app/manifests/latest", index, contentType(MediaTypeOCIIndex))
	h.expectStatus(resp, http.StatusCreated, "put index")
	indexDigest := store.Digest(index)

	// Before any SBOM exists, both lookups report nothing.
	resp = h.do(http.MethodGet, "/api/repositories/team-a/app/manifests/"+indexDigest+"/sbom", nil)
	h.expectStatus(resp, http.StatusNotFound, "index with no SBOM anywhere")

	// Attach an SBOM to the child, exactly as the generator does.
	attachSBOM(h, "team-a/app", child)

	// Asking the index must now find the child's SBOM.
	resp = h.do(http.MethodGet, "/api/repositories/team-a/app/manifests/"+indexDigest+"/sbom", nil)
	body := h.expectStatus(resp, http.StatusOK, "SBOM resolved through the index")
	if !bytes.Contains(body, []byte("CycloneDX")) {
		t.Fatalf("unexpected document: %s", body)
	}
	if got := resp.Header.Get("X-Registry-Sbom-Platform"); got != "linux/amd64" {
		t.Errorf("platform header = %q, want linux/amd64", got)
	}

	// And the manifest detail the UI renders must show it too.
	var detail struct {
		SBOM map[string]any `json:"sbom"`
	}
	h.mustJSON(h.do(http.MethodGet, "/api/repositories/team-a/app/manifests/"+indexDigest, nil),
		http.StatusOK, &detail)
	if detail.SBOM == nil {
		t.Fatal("manifest detail for an index reported no SBOM")
	}
	_ = ctx
}

// A genuinely multi-platform index has one SBOM per platform, so the caller has
// to disambiguate rather than silently receive an arbitrary one.
func TestSBOMMultiPlatformIndexRequiresChoice(t *testing.T) {
	h := newHarness(t)
	amd := h.pushImage("team-a/multi", "sha-amd64")
	arm := h.pushImage("team-a/multi", "sha-arm64", "arm-layer")

	index, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2, MediaType: MediaTypeOCIIndex,
		Manifests: []descriptor{
			{MediaType: MediaTypeOCIManifest, Digest: amd, Size: 100,
				Platform: &platform{OS: "linux", Architecture: "amd64"}},
			{MediaType: MediaTypeOCIManifest, Digest: arm, Size: 100,
				Platform: &platform{OS: "linux", Architecture: "arm64"}},
		},
	})
	h.do(http.MethodPut, "/v2/team-a/multi/manifests/latest", index, contentType(MediaTypeOCIIndex)).Body.Close()
	indexDigest := store.Digest(index)

	attachSBOM(h, "team-a/multi", amd)
	attachSBOM(h, "team-a/multi", arm)

	// Ambiguous without a platform, and the error must name the options.
	resp := h.do(http.MethodGet, "/api/repositories/team-a/multi/manifests/"+indexDigest+"/sbom", nil)
	body := h.expectStatus(resp, http.StatusBadRequest, "ambiguous multi-platform SBOM")
	for _, want := range []string{"linux/amd64", "linux/arm64"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("error should list %s; got %s", want, body)
		}
	}

	// Naming a platform resolves it.
	resp = h.do(http.MethodGet,
		"/api/repositories/team-a/multi/manifests/"+indexDigest+"/sbom?platform=linux/arm64", nil)
	h.expectStatus(resp, http.StatusOK, "SBOM selected by platform")
	if got := resp.Header.Get("X-Registry-Sbom-Platform"); got != "linux/arm64" {
		t.Errorf("platform header = %q", got)
	}

	// A platform that was never built is a clean 404.
	resp = h.do(http.MethodGet,
		"/api/repositories/team-a/multi/manifests/"+indexDigest+"/sbom?platform=windows/amd64", nil)
	h.expectStatus(resp, http.StatusNotFound, "unknown platform")
}

// attachSBOM publishes a minimal CycloneDX referrer against a manifest, the
// same shape the generator produces.
func attachSBOM(h *harness, repo, subject string) {
	h.t.Helper()
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`)
	docDigest := h.pushBlob(repo, doc)
	empty := h.pushBlob(repo, []byte("{}"))

	artifact, _ := json.Marshal(manifestDoc{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		ArtifactType:  "application/vnd.cyclonedx+json",
		Config:        &descriptor{MediaType: MediaTypeOCIEmptyJSON, Digest: empty, Size: 2},
		Layers: []descriptor{{
			MediaType: "application/vnd.cyclonedx+json", Digest: docDigest, Size: int64(len(doc)),
		}},
		Subject: &descriptor{MediaType: MediaTypeOCIManifest, Digest: subject, Size: 100},
	})
	resp := h.do(http.MethodPut, "/v2/"+repo+"/manifests/"+store.Digest(artifact),
		artifact, contentType(MediaTypeOCIManifest))
	h.expectStatus(resp, http.StatusCreated, "attach SBOM referrer")
}
