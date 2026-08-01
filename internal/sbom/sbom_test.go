package sbom

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/store"
)

// ---------------------------------------------------------------- fixtures

const alpineDB = `C:Q1eVpkasdf
P:musl
V:1.2.5-r0
A:x86_64
L:MIT
T:the musl c library

C:Q1other
P:busybox
V:1.36.1-r29
A:x86_64
L:GPL-2.0-only

C:Q1third
P:apk-tools
V:2.14.4-r1
A:x86_64
L:GPL-2.0-only
`

const dpkgStatus = `Package: adduser
Status: install ok installed
Priority: important
Version: 3.134
Architecture: all
Description: add and remove users
 This package includes the adduser command.

Package: removed-but-configured
Status: deinstall ok config-files
Version: 1.0
Architecture: amd64

Package: libc6
Status: install ok installed
Version: 2.36-9+deb12u7
Architecture: amd64
`

// tarLayer builds a gzip-compressed tar layer from a path -> content map.
func tarLayer(t *testing.T, files map[string]string, modes map[string]int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, content := range files {
		mode := int64(0o644)
		if m, ok := modes[name]; ok {
			mode = m
		}
		hdr := &tar.Header{
			Name: name, Mode: mode, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// tarLayerUncompressed builds a plain tar, for compressing another way.
func tarLayerUncompressed(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func layerFrom(b []byte) LayerSource {
	return LayerSource{
		Digest:    store.Digest(b),
		MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
		Open:      func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil },
	}
}

// ---------------------------------------------------------------- parsers

func TestParseAPK(t *testing.T) {
	pkgs := parseAPK([]byte(alpineDB))
	if len(pkgs) != 3 {
		t.Fatalf("parsed %d packages, want 3: %+v", len(pkgs), pkgs)
	}
	got := pkgs[0]
	if got.Name != "musl" || got.Version != "1.2.5-r0" || got.Arch != "x86_64" || got.License != "MIT" {
		t.Fatalf("first package = %+v", got)
	}
	if got.Ecosystem != "apk" {
		t.Errorf("ecosystem = %q", got.Ecosystem)
	}
	if want := "pkg:apk/alpine-3.20/musl@1.2.5-r0?arch=x86_64"; got.purl("alpine-3.20") != want {
		t.Errorf("purl = %q, want %q", got.purl("alpine-3.20"), want)
	}
}

func TestParseDpkgSkipsUninstalled(t *testing.T) {
	pkgs := parseDpkg([]byte(dpkgStatus))
	if len(pkgs) != 2 {
		t.Fatalf("parsed %d packages, want 2 (the deinstalled one must be dropped): %+v", len(pkgs), pkgs)
	}
	names := []string{pkgs[0].Name, pkgs[1].Name}
	if names[0] != "adduser" || names[1] != "libc6" {
		t.Fatalf("packages = %v", names)
	}
	if pkgs[1].Version != "2.36-9+deb12u7" {
		t.Errorf("libc6 version = %q", pkgs[1].Version)
	}
	// Continuation lines in the Description field must not be misread as fields.
	if pkgs[0].Version != "3.134" {
		t.Errorf("adduser version = %q; a continuation line was misparsed", pkgs[0].Version)
	}
}

func TestDistroFrom(t *testing.T) {
	cases := map[string]string{
		"ID=alpine\nVERSION_ID=3.20.3\n":         "alpine-3.20.3",
		"ID=debian\nVERSION_ID=\"12\"\n":         "debian-12",
		"PRETTY_NAME=\"Something\"\nID=ubuntu\n": "ubuntu",
		"":                                       "",
	}
	for input, want := range cases {
		if got := distroFrom(input); got != want {
			t.Errorf("distroFrom(%q) = %q, want %q", input, got, want)
		}
	}
}

// ---------------------------------------------------------------- scanning

func TestScanReadsPackageDatabases(t *testing.T) {
	layer := tarLayer(t, map[string]string{
		"lib/apk/db/installed": alpineDB,
		"etc/os-release":       "ID=alpine\nVERSION_ID=3.20.3\n",
		"bin/irrelevant":       "not a package database",
	}, nil)

	res, err := Scan([]LayerSource{layerFrom(layer)}, DefaultLimits())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Distro != "alpine-3.20.3" {
		t.Errorf("distro = %q", res.Distro)
	}
	if len(res.Packages) != 3 {
		t.Fatalf("found %d packages, want 3", len(res.Packages))
	}
}

// A later layer replaces the package database contributed by an earlier one,
// which is what happens when a derived image installs more packages.
func TestScanLaterLayerWins(t *testing.T) {
	base := tarLayer(t, map[string]string{"lib/apk/db/installed": alpineDB}, nil)
	upper := tarLayer(t, map[string]string{
		"lib/apk/db/installed": "P:only-this\nV:9.9\nA:x86_64\n",
	}, nil)

	res, err := Scan([]LayerSource{layerFrom(base), layerFrom(upper)}, DefaultLimits())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "only-this" {
		t.Fatalf("packages = %+v, want only the upper layer's database", res.Packages)
	}
}

func TestScanHonoursWhiteouts(t *testing.T) {
	base := tarLayer(t, map[string]string{"lib/apk/db/installed": alpineDB}, nil)
	// A whiteout entry deletes the file from the lower layer.
	deleted := tarLayer(t, map[string]string{"lib/apk/db/.wh.installed": ""}, nil)

	res, err := Scan([]LayerSource{layerFrom(base), layerFrom(deleted)}, DefaultLimits())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Packages) != 0 {
		t.Fatalf("packages = %+v, want none after the database was whited out", res.Packages)
	}
}

// zstd layers are decompressed rather than skipped. They were previously
// ignored for want of a decoder, which silently under-reported any image built
// with zstd compression.
func TestScanReadsZstdLayers(t *testing.T) {
	raw := tarLayerUncompressed(t, map[string]string{"lib/apk/db/installed": alpineDB})
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("compress: %v", err)
	}
	zw.Close()
	compressed := buf.Bytes()

	layer := LayerSource{
		Digest:    store.Digest(compressed),
		MediaType: "application/vnd.oci.image.layer.v1.tar+zstd",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(compressed)), nil
		},
	}
	res, err := Scan([]LayerSource{layer}, DefaultLimits())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Packages) != 3 {
		t.Fatalf("found %d packages in a zstd layer, want 3", len(res.Packages))
	}
}

// A layer that claims to be zstd but is not must not sink the whole scan.
func TestScanToleratesCorruptZstdLayer(t *testing.T) {
	good := tarLayer(t, map[string]string{"lib/apk/db/installed": alpineDB}, nil)
	bad := LayerSource{
		Digest:    store.Digest([]byte("not-zstd")),
		MediaType: "application/vnd.oci.image.layer.v1.tar+zstd",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("this is not compressed at all")), nil
		},
	}
	res, err := Scan([]LayerSource{layerFrom(good), bad}, DefaultLimits())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Packages) != 3 {
		t.Fatalf("the readable layer should still be scanned; got %d", len(res.Packages))
	}
}

func TestScanRespectsEntryLimit(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 100; i++ {
		files[string(rune('a'+i%26))+"/f"+string(rune('0'+i%10))+".txt"] = "x"
	}
	files["lib/apk/db/installed"] = alpineDB
	layer := tarLayer(t, files, nil)

	limits := DefaultLimits()
	limits.MaxEntries = 5
	// The scan must stop early rather than run away, and must not error.
	if _, err := Scan([]LayerSource{layerFrom(layer)}, limits); err != nil {
		t.Fatalf("Scan with a tight entry budget: %v", err)
	}
}

// ---------------------------------------------------------------- components

func TestToComponentsIsDeterministicAndDeduplicated(t *testing.T) {
	in := []pkg{
		{Name: "zlib", Version: "1.3", Ecosystem: "apk"},
		{Name: "musl", Version: "1.2.5", Ecosystem: "apk"},
		{Name: "zlib", Version: "1.3", Ecosystem: "apk"}, // duplicate
		{Name: "", Version: "1.0", Ecosystem: "apk"},     // nameless, dropped
	}
	first := toComponents(in, "alpine")
	if len(first) != 2 {
		t.Fatalf("got %d components, want 2 after de-duplication: %+v", len(first), first)
	}
	if first[0].Name != "musl" || first[1].Name != "zlib" {
		t.Fatalf("components are not sorted: %+v", first)
	}
	// Re-running must produce identical output, so an unchanged image yields an
	// unchanged document.
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(toComponents(in, "alpine"))
	if !bytes.Equal(a, b) {
		t.Fatal("component rendering is not deterministic")
	}
}

// ---------------------------------------------------------------- generator

type harness struct {
	gen   *Generator
	db    *db.DB
	store *store.Store
	repo  *db.Repository
}

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
	repo, err := database.EnsureRepository(context.Background(), "team/app")
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}
	g := New(database, st, slog.New(slog.NewTextHandler(io.Discard, nil)), 1, 4)
	return &harness{gen: g, db: database, store: st, repo: repo}
}

// pushImage stores a minimal image whose single layer carries an apk database.
func (h *harness) pushImage(t *testing.T) string {
	t.Helper()
	layer := tarLayer(t, map[string]string{
		"lib/apk/db/installed": alpineDB,
		"etc/os-release":       "ID=alpine\nVERSION_ID=3.20.3\n",
	}, nil)
	layerDigest, err := h.store.For("test/repo").PutBytes(layer)
	if err != nil {
		t.Fatalf("store layer: %v", err)
	}
	cfg := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgDigest, _ := h.store.For("test/repo").PutBytes(cfg)

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     ociManifestMediaType,
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    cfgDigest, "size": len(cfg),
		},
		"layers": []map[string]any{{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest":    layerDigest, "size": len(layer),
		}},
	}
	body, _ := json.Marshal(manifest)
	digest, _ := h.store.For("test/repo").PutBytes(body)

	ctx := context.Background()
	if err := h.db.PutManifest(ctx, &db.Manifest{
		RepoID: h.repo.ID, Digest: digest, MediaType: ociManifestMediaType,
		Size: int64(len(body)), ConfigDigest: cfgDigest,
	}, []db.ManifestRef{
		{Digest: cfgDigest, Kind: "config", Size: int64(len(cfg))},
		{Digest: layerDigest, Kind: "layer", Size: int64(len(layer))},
	}); err != nil {
		t.Fatalf("record manifest: %v", err)
	}
	h.db.LinkBlob(ctx, h.repo.ID, layerDigest, int64(len(layer)))
	h.db.LinkBlob(ctx, h.repo.ID, cfgDigest, int64(len(cfg)))
	h.db.LinkBlob(ctx, h.repo.ID, digest, int64(len(body)))
	return digest
}

func TestGeneratePublishesReferrer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	digest := h.pushImage(t)

	job := Job{RepoID: h.repo.ID, RepoName: "team/app", Digest: digest}
	generated, err := h.gen.Generate(ctx, job)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !generated {
		t.Fatal("Generate reported no work for a scannable image")
	}

	// The SBOM must be attached to the image through the referrers relation.
	refs, err := h.db.Referrers(ctx, h.repo.ID, digest, MediaType)
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("found %d referrers, want 1", len(refs))
	}
	if refs[0].ArtifactType != MediaType {
		t.Errorf("artifactType = %q, want %q", refs[0].ArtifactType, MediaType)
	}

	// And the document itself must be well-formed CycloneDX naming the packages.
	artBody, err := h.store.For("test/repo").ReadAll(refs[0].Digest)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var art artifactManifest
	if err := json.Unmarshal(artBody, &art); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	if art.Subject == nil || art.Subject.Digest != digest {
		t.Fatalf("artifact subject = %+v, want the image digest", art.Subject)
	}
	if len(art.Layers) != 1 {
		t.Fatalf("artifact has %d layers, want 1", len(art.Layers))
	}
	docBody, err := h.store.For("test/repo").ReadAll(art.Layers[0].Digest)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	var doc Document
	if err := json.Unmarshal(docBody, &doc); err != nil {
		t.Fatalf("parse document: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != SpecVersion {
		t.Errorf("document header = %s %s", doc.BOMFormat, doc.SpecVersion)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("document has %d components, want 3", len(doc.Components))
	}
	if doc.Metadata.Component == nil || doc.Metadata.Component.Name != "team/app" {
		t.Errorf("metadata component = %+v", doc.Metadata.Component)
	}
}

// Generating twice must not produce a second SBOM.
func TestGenerateIsIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	digest := h.pushImage(t)
	job := Job{RepoID: h.repo.ID, RepoName: "team/app", Digest: digest}

	if _, err := h.gen.Generate(ctx, job); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	generated, err := h.gen.Generate(ctx, job)
	if err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	if generated {
		t.Fatal("a second run produced another SBOM instead of skipping")
	}
	refs, _ := h.db.Referrers(ctx, h.repo.ID, digest, MediaType)
	if len(refs) != 1 {
		t.Fatalf("found %d SBOM referrers, want exactly 1", len(refs))
	}
}

// The generator must never describe its own output, which would recurse.
func TestGeneratorSkipsItsOwnArtifacts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	digest := h.pushImage(t)
	job := Job{RepoID: h.repo.ID, RepoName: "team/app", Digest: digest}

	if _, err := h.gen.Generate(ctx, job); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	refs, _ := h.db.Referrers(ctx, h.repo.ID, digest, MediaType)
	sbomDigest := refs[0].Digest

	// Feed the SBOM artifact back in as if it had just been pushed.
	generated, err := h.gen.Generate(ctx, Job{
		RepoID: h.repo.ID, RepoName: "team/app", Digest: sbomDigest,
	})
	if err != nil {
		t.Fatalf("Generate over an artifact: %v", err)
	}
	if generated {
		t.Fatal("the generator described its own SBOM artifact")
	}
}

func TestScannableRejectsArtifactsAndIndexes(t *testing.T) {
	cases := []struct {
		name string
		m    imageManifest
		want bool
	}{
		{"plain image", imageManifest{
			Config: &descriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
			Layers: []descriptor{{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:x",
			}},
		}, true},
		{"referrer artifact", imageManifest{
			Subject: &descriptor{Digest: "sha256:y"},
			Layers: []descriptor{{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:x",
			}},
		}, false},
		{"non-image artifact", imageManifest{
			ArtifactType: "application/vnd.example.thing",
			Config:       &descriptor{MediaType: emptyJSONMediaType},
			Layers:       []descriptor{{Digest: "sha256:x"}},
		}, false},
		{"empty", imageManifest{}, false},
	}
	for _, c := range cases {
		if got := scannable(&c.m); got != c.want {
			t.Errorf("%s: scannable = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEnqueueNeverBlocksWhenFull(t *testing.T) {
	h := newHarness(t)
	// Workers are never started, so nothing drains the queue.
	for i := 0; i < 50; i++ {
		h.gen.Enqueue(Job{RepoID: h.repo.ID, RepoName: "team/app", Digest: store.Digest([]byte{byte(i)})})
	}
	st := h.gen.Stats()
	if st.Dropped == 0 {
		t.Fatal("a saturated queue must drop jobs rather than block the push path")
	}
}

func TestUUIDFromDigestIsStable(t *testing.T) {
	d := store.Digest([]byte("some manifest"))
	if uuidFromDigest(d) != uuidFromDigest(d) {
		t.Fatal("serial number derivation is not stable")
	}
	if len(uuidFromDigest(d)) != 36 {
		t.Fatalf("serial %q is not UUID-shaped", uuidFromDigest(d))
	}
}

// A build attestation rides inside an index looking much like an image, but its
// layers are in-toto documents rather than a root filesystem. Describing one
// would publish an empty SBOM against something that is not an image.
func TestScannableRejectsBuildAttestations(t *testing.T) {
	attestation := imageManifest{
		MediaType: ociManifestMediaType,
		Config:    &descriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []descriptor{
			{MediaType: "application/vnd.in-toto+json", Digest: "sha256:a"},
			{MediaType: "application/vnd.in-toto+json", Digest: "sha256:b"},
		},
	}
	if scannable(&attestation) {
		t.Fatal("a build attestation manifest must not be scanned as an image")
	}

	// The same shape with a real filesystem layer is an image and must be kept.
	image := attestation
	image.Layers = []descriptor{
		{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:c"},
	}
	if !scannable(&image) {
		t.Fatal("an ordinary image must still be scannable")
	}

	// Docker's own layer vocabulary counts too.
	dockerImage := attestation
	dockerImage.Config = &descriptor{MediaType: "application/vnd.docker.container.image.v1+json"}
	dockerImage.Layers = []descriptor{
		{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Digest: "sha256:d"},
	}
	if !scannable(&dockerImage) {
		t.Fatal("a Docker-schema image must still be scannable")
	}
}
