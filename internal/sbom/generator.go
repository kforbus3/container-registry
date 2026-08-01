package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/store"
)

// emptyJSONMediaType is the descriptor OCI defines for artifacts that have no
// meaningful config blob.
const emptyJSONMediaType = "application/vnd.oci.empty.v1+json"

const (
	ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	sbomLayerMediaType   = "application/vnd.cyclonedx+json"
)

// descriptor mirrors the OCI content descriptor. It is redeclared here so this
// package does not depend on the HTTP layer.
type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

type artifactManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Subject       *descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// imageManifest is the subset of a pushed manifest the generator needs.
type imageManifest struct {
	MediaType    string       `json:"mediaType"`
	ArtifactType string       `json:"artifactType"`
	Config       *descriptor  `json:"config"`
	Layers       []descriptor `json:"layers"`
	Manifests    []descriptor `json:"manifests"`
	Subject      *descriptor  `json:"subject"`
}

// Job identifies one image to describe.
type Job struct {
	RepoID   int64
	RepoName string
	Digest   string
}

// Generator scans pushed images and publishes an SBOM for each as an OCI
// referrer. Work happens on background workers so a push is never slowed by it.
type Generator struct {
	DB     *db.DB
	Store  *store.Store
	Log    *slog.Logger
	Limits Limits

	// OnPublished, when set, is called after an SBOM is written. It is how
	// vulnerability scanning is chained on without this package having to know
	// anything about it.
	OnPublished func(job Job)

	queue chan Job
	wg    sync.WaitGroup

	mu       sync.Mutex
	inflight map[string]bool
	stats    Stats
}

// Stats reports what the generator has done since start-up.
type Stats struct {
	Queued    int64 `json:"queued"`
	Generated int64 `json:"generated"`
	Skipped   int64 `json:"skipped"`
	Failed    int64 `json:"failed"`
	Dropped   int64 `json:"dropped"`
}

// New creates a generator with the given number of workers and queue depth.
func New(database *db.DB, st *store.Store, log *slog.Logger, workers, queueDepth int) *Generator {
	if workers <= 0 {
		workers = 2
	}
	if queueDepth <= 0 {
		queueDepth = 256
	}
	return &Generator{
		DB: database, Store: st, Log: log, Limits: DefaultLimits(),
		queue:    make(chan Job, queueDepth),
		inflight: map[string]bool{},
	}
}

// Start launches the worker pool. It returns immediately.
func (g *Generator) Start(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-g.queue:
					if !ok {
						return
					}
					g.run(ctx, job)
				}
			}
		}()
	}
}

// Wait blocks until the workers have stopped. Used on shutdown.
func (g *Generator) Wait() { g.wg.Wait() }

func (g *Generator) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stats
}

// Enqueue schedules an image for scanning. It never blocks: if the queue is
// full the job is dropped and counted, because a push must not wait on SBOM
// capacity.
func (g *Generator) Enqueue(job Job) {
	key := fmt.Sprintf("%d/%s", job.RepoID, job.Digest)
	g.mu.Lock()
	if g.inflight[key] {
		g.mu.Unlock()
		return
	}
	g.inflight[key] = true
	g.stats.Queued++
	g.mu.Unlock()

	select {
	case g.queue <- job:
	default:
		g.mu.Lock()
		delete(g.inflight, key)
		g.stats.Dropped++
		g.mu.Unlock()
		g.Log.Warn("sbom queue full, dropping job", "repo", job.RepoName, "digest", job.Digest)
	}
}

func (g *Generator) run(ctx context.Context, job Job) {
	key := fmt.Sprintf("%d/%s", job.RepoID, job.Digest)
	defer func() {
		g.mu.Lock()
		delete(g.inflight, key)
		g.mu.Unlock()
	}()
	defer func() {
		if rec := recover(); rec != nil {
			g.Log.Error("sbom generation panicked",
				"repo", job.RepoName, "digest", job.Digest, "panic", rec)
			g.mu.Lock()
			g.stats.Failed++
			g.mu.Unlock()
		}
	}()

	generated, err := g.Generate(ctx, job)
	g.mu.Lock()
	switch {
	case err != nil:
		g.stats.Failed++
	case generated:
		g.stats.Generated++
	default:
		g.stats.Skipped++
	}
	g.mu.Unlock()

	if err != nil {
		g.Log.Error("sbom generation failed", "repo", job.RepoName, "digest", job.Digest, "err", err)
	}
}

// Generate produces and publishes an SBOM for one image. It reports whether a
// new SBOM was written; an image that is not scannable, or that already has an
// SBOM, is skipped without error.
func (g *Generator) Generate(ctx context.Context, job Job) (bool, error) {
	raw, err := g.Store.ReadAll(job.Digest)
	if err != nil {
		return false, fmt.Errorf("read manifest: %w", err)
	}
	var m imageManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return false, fmt.Errorf("parse manifest: %w", err)
	}
	if !scannable(&m) {
		return false, nil
	}
	// An index needs no SBOM of its own: each platform manifest it points at
	// was pushed separately and described on its own.
	if len(m.Manifests) > 0 {
		return false, nil
	}
	if has, err := g.hasSBOM(ctx, job); err != nil || has {
		return false, err
	}

	layers := make([]LayerSource, 0, len(m.Layers))
	skippedZstd := 0
	for _, l := range m.Layers {
		if strings.HasSuffix(l.MediaType, "+zstd") {
			skippedZstd++
		}
		src := LayerSource{Digest: l.Digest, MediaType: l.MediaType}
		src.Open = func() (io.ReadCloser, error) {
			f, _, err := g.Store.Open(src.Digest)
			return f, err
		}
		layers = append(layers, src)
	}

	scan, err := Scan(layers, g.Limits)
	if err != nil {
		return false, fmt.Errorf("scan layers: %w", err)
	}

	doc := g.document(job, &m, scan, skippedZstd)
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode sbom: %w", err)
	}
	if err := g.publish(ctx, job, &m, body, len(doc.Components)); err != nil {
		return false, err
	}
	g.Log.Info("sbom published",
		"repo", job.RepoName, "digest", job.Digest,
		"components", len(doc.Components), "distro", scan.Distro)
	if g.OnPublished != nil {
		g.OnPublished(job)
	}
	return true, nil
}

// scannable filters out manifests that describe something other than a runnable
// image — including the SBOMs this generator itself publishes, which would
// otherwise cause it to describe its own output forever.
func scannable(m *imageManifest) bool {
	if m.Subject != nil {
		return false // this manifest is itself a referrer artifact
	}
	if m.ArtifactType != "" && m.ArtifactType != "application/vnd.oci.image.config.v1+json" {
		return false
	}
	if m.Config != nil {
		switch m.Config.MediaType {
		case "application/vnd.oci.image.config.v1+json",
			"application/vnd.docker.container.image.v1+json":
		default:
			return false
		}
	}
	if len(m.Manifests) > 0 {
		return true // an index; handled separately by the caller
	}
	// Require at least one real filesystem layer. Build attestations ride
	// inside an index as manifests that look like images but carry in-toto
	// documents instead of a root filesystem; describing them would publish an
	// empty SBOM against something that is not an image.
	for _, l := range m.Layers {
		if isFilesystemLayer(l.MediaType) {
			return true
		}
	}
	return false
}

// isFilesystemLayer reports whether a layer media type is a root-filesystem
// layer, in either the OCI or the Docker vocabulary.
func isFilesystemLayer(mt string) bool {
	switch mt {
	case "application/vnd.oci.image.layer.v1.tar",
		"application/vnd.oci.image.layer.v1.tar+gzip",
		"application/vnd.oci.image.layer.v1.tar+zstd",
		"application/vnd.oci.image.layer.nondistributable.v1.tar",
		"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
		"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
		"application/vnd.docker.image.rootfs.diff.tar.gzip",
		"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		return true
	}
	return false
}

func (g *Generator) hasSBOM(ctx context.Context, job Job) (bool, error) {
	existing, err := g.DB.Referrers(ctx, job.RepoID, job.Digest, MediaType)
	if err != nil {
		return false, err
	}
	return len(existing) > 0, nil
}

func (g *Generator) document(job Job, m *imageManifest, scan *Result, skippedZstd int) *Document {
	distro := scan.Distro
	components := toComponents(scan.Packages, distro)

	image := &Component{
		Type:   "container",
		BOMRef: job.Digest,
		Name:   job.RepoName,
		PURL:   fmt.Sprintf("pkg:oci/%s@%s", lastPathSegment(job.RepoName), job.Digest),
		Hashes: []Hash{{Algorithm: "SHA-256", Content: strings.TrimPrefix(job.Digest, "sha256:")}},
	}
	if distro != "" {
		image.Properties = append(image.Properties, Property{Name: "registry:distro", Value: distro})
	}
	image.Properties = append(image.Properties,
		Property{Name: "registry:manifestDigest", Value: job.Digest},
		Property{Name: "registry:layerCount", Value: fmt.Sprint(len(m.Layers))},
	)
	if skippedZstd > 0 {
		// Recorded rather than hidden: a partial scan must be visible in the
		// document itself, not just in the server log.
		image.Properties = append(image.Properties, Property{
			Name:  "registry:skippedLayers",
			Value: fmt.Sprintf("%d zstd-compressed layer(s) were not scanned", skippedZstd),
		})
	}
	if scan.ManifestsTruncated {
		image.Properties = append(image.Properties, Property{
			Name:  "registry:truncated",
			Value: "the language-package limit was reached; this component list is incomplete",
		})
	}

	return &Document{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: "urn:uuid:" + uuidFromDigest(job.Digest),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []Tool{{Vendor: "container-registry", Name: "registry-sbom", Version: "1"}},
			Component: image,
		},
		Components: components,
	}
}

// publish writes the SBOM as a blob and attaches it to the image with an OCI
// artifact manifest whose subject is the image, so it is discoverable through
// the referrers API.
func (g *Generator) publish(ctx context.Context, job Job, m *imageManifest, body []byte, components int) error {
	sbomDigest, err := g.Store.PutBytes(body)
	if err != nil {
		return fmt.Errorf("store sbom blob: %w", err)
	}
	emptyDigest, err := g.Store.PutBytes([]byte("{}"))
	if err != nil {
		return fmt.Errorf("store empty config: %w", err)
	}

	art := artifactManifest{
		SchemaVersion: 2,
		MediaType:     ociManifestMediaType,
		ArtifactType:  MediaType,
		Config:        descriptor{MediaType: emptyJSONMediaType, Digest: emptyDigest, Size: 2},
		Layers: []descriptor{{
			MediaType: sbomLayerMediaType,
			Digest:    sbomDigest,
			Size:      int64(len(body)),
			Annotations: map[string]string{
				"org.opencontainers.image.title": "sbom.cdx.json",
			},
		}},
		Subject: &descriptor{
			MediaType: manifestMediaTypeOf(m),
			Digest:    job.Digest,
			Size:      int64(len(body)),
		},
		Annotations: map[string]string{
			"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
			"org.opencontainers.artifact.type": MediaType,
			"registry.sbom.componentCount":     fmt.Sprint(components),
			"registry.sbom.generatedBy":        "container-registry",
		},
	}
	// The subject descriptor must carry the subject's own size.
	if raw, err := g.Store.ReadAll(job.Digest); err == nil {
		art.Subject.Size = int64(len(raw))
	}

	artBody, err := json.Marshal(art)
	if err != nil {
		return fmt.Errorf("encode artifact manifest: %w", err)
	}
	artDigest, err := g.Store.PutBytes(artBody)
	if err != nil {
		return fmt.Errorf("store artifact manifest: %w", err)
	}

	refs := []db.ManifestRef{
		{Digest: emptyDigest, Kind: "config", Size: 2},
		{Digest: sbomDigest, Kind: "layer", Size: int64(len(body))},
	}
	record := &db.Manifest{
		RepoID:       job.RepoID,
		Digest:       artDigest,
		MediaType:    ociManifestMediaType,
		ArtifactType: MediaType,
		Subject:      job.Digest,
		Size:         int64(len(artBody)),
		ConfigDigest: emptyDigest,
	}
	if err := g.DB.PutManifest(ctx, record, refs); err != nil {
		return fmt.Errorf("record artifact manifest: %w", err)
	}
	// Link every blob the artifact depends on, plus the artifact manifest
	// itself, so garbage collection treats it as live.
	for _, d := range []struct {
		digest string
		size   int64
	}{
		{emptyDigest, 2},
		{sbomDigest, int64(len(body))},
		{artDigest, int64(len(artBody))},
	} {
		if err := g.DB.LinkBlob(ctx, job.RepoID, d.digest, d.size); err != nil {
			return fmt.Errorf("link blob %s: %w", d.digest, err)
		}
	}
	g.DB.Audit(ctx, "registry", "sbom.generate", job.RepoName, job.Digest,
		fmt.Sprintf("%d components", components), "")
	return nil
}

func manifestMediaTypeOf(m *imageManifest) string {
	if m.MediaType != "" {
		return m.MediaType
	}
	return ociManifestMediaType
}

func lastPathSegment(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// uuidFromDigest derives a stable RFC 4122-shaped identifier from a digest, so
// re-describing the same image yields the same serial number.
func uuidFromDigest(digest string) string {
	hexPart := digest
	if i := strings.IndexByte(digest, ':'); i >= 0 {
		hexPart = digest[i+1:]
	}
	if len(hexPart) < 32 {
		hexPart = (hexPart + strings.Repeat("0", 32))[:32]
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexPart[0:8], hexPart[8:12], hexPart[12:16], hexPart[16:20], hexPart[20:32])
}
