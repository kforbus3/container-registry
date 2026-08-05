package api

import (
	"encoding/json"
	"fmt"

	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/store"
)

// Media types this registry accepts and serves.
const (
	MediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerManifestV1   = "application/vnd.docker.distribution.manifest.v1+json"
	MediaTypeDockerManifestV1S  = "application/vnd.docker.distribution.manifest.v1+prettyjws"
	MediaTypeOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex           = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIEmptyJSON       = "application/vnd.oci.empty.v1+json"
)

// supportedManifestTypes is consulted when a client PUTs a manifest.
var supportedManifestTypes = map[string]bool{
	MediaTypeDockerManifest:     true,
	MediaTypeDockerManifestList: true,
	MediaTypeOCIManifest:        true,
	MediaTypeOCIIndex:           true,
}

func isIndexType(mt string) bool {
	return mt == MediaTypeDockerManifestList || mt == MediaTypeOCIIndex
}

// descriptor is the OCI content descriptor shared by configs, layers and
// index entries.
type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	URLs         []string          `json:"urls,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Platform     *platform         `json:"platform,omitempty"`
}

type platform struct {
	Architecture string   `json:"architecture,omitempty"`
	OS           string   `json:"os,omitempty"`
	OSVersion    string   `json:"os.version,omitempty"`
	Variant      string   `json:"variant,omitempty"`
	Features     []string `json:"features,omitempty"`
}

// manifestDoc covers both image manifests and indexes; only the fields
// relevant to one shape are populated.
type manifestDoc struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Config        *descriptor       `json:"config,omitempty"`
	Layers        []descriptor      `json:"layers,omitempty"`
	Manifests     []descriptor      `json:"manifests,omitempty"`
	Subject       *descriptor       `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// parsedManifest is the normalised result of inspecting a manifest payload.
type parsedManifest struct {
	MediaType    string
	ArtifactType string
	Subject      string
	ConfigDigest string
	Refs         []db.ManifestRef
	Doc          *manifestDoc
}

// parseManifest validates a manifest payload and extracts everything the
// registry needs to index it. contentType is the request's Content-Type, used
// only when the document omits its own mediaType (Docker schema 2 allows this).
func parseManifest(body []byte, contentType string) (*parsedManifest, error) {
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}

	mt := doc.MediaType
	if mt == "" {
		mt = contentType
	}
	if mt == "" {
		// Infer from shape as a last resort.
		if len(doc.Manifests) > 0 {
			mt = MediaTypeOCIIndex
		} else {
			mt = MediaTypeOCIManifest
		}
	}
	if mt == MediaTypeDockerManifestV1 || mt == MediaTypeDockerManifestV1S {
		//lint:ignore ST1005 the message names Docker, a proper noun, not a sentence start
		return nil, fmt.Errorf("Docker manifest schema 1 is not supported; push with a modern client")
	}
	if !supportedManifestTypes[mt] {
		return nil, fmt.Errorf("unsupported manifest media type %q", mt)
	}
	if doc.SchemaVersion != 0 && doc.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported schemaVersion %d", doc.SchemaVersion)
	}

	p := &parsedManifest{MediaType: mt, ArtifactType: doc.ArtifactType, Doc: &doc}

	if doc.Subject != nil {
		if !store.ValidDigest(doc.Subject.Digest) {
			return nil, fmt.Errorf("subject has invalid digest %q", doc.Subject.Digest)
		}
		p.Subject = doc.Subject.Digest
	}

	if isIndexType(mt) {
		if doc.Config != nil || len(doc.Layers) > 0 {
			return nil, fmt.Errorf("index must not carry config or layers")
		}
		for i, m := range doc.Manifests {
			if !store.ValidDigest(m.Digest) {
				return nil, fmt.Errorf("manifests[%d] has invalid digest %q", i, m.Digest)
			}
			p.Refs = append(p.Refs, db.ManifestRef{Digest: m.Digest, Kind: "manifest", Size: m.Size})
		}
		return p, nil
	}

	// Image manifest: config is required by the spec.
	if doc.Config == nil {
		return nil, fmt.Errorf("image manifest is missing config")
	}
	if !store.ValidDigest(doc.Config.Digest) {
		return nil, fmt.Errorf("config has invalid digest %q", doc.Config.Digest)
	}
	p.ConfigDigest = doc.Config.Digest
	p.Refs = append(p.Refs, db.ManifestRef{Digest: doc.Config.Digest, Kind: "config", Size: doc.Config.Size})

	for i, l := range doc.Layers {
		if !store.ValidDigest(l.Digest) {
			return nil, fmt.Errorf("layers[%d] has invalid digest %q", i, l.Digest)
		}
		// Foreign//nondistributable layers live elsewhere; they are recorded but
		// never required to be present locally.
		p.Refs = append(p.Refs, db.ManifestRef{Digest: l.Digest, Kind: layerKind(l), Size: l.Size})
	}
	// OCI 1.1: when a manifest carries no artifactType, its artifact type *is*
	// config.mediaType. This holds for ordinary images too — a plain image
	// referenced as a referrer reports the standard config type — so there is
	// no exemption for the well-known config media types.
	if p.ArtifactType == "" {
		p.ArtifactType = doc.Config.MediaType
	}
	return p, nil
}

func layerKind(d descriptor) string {
	switch d.MediaType {
	case "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
		"application/vnd.oci.image.layer.nondistributable.v1.tar",
		"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
		"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd":
		return "foreign"
	}
	return "layer"
}

// imageConfig is the subset of an image config document surfaced in the UI.
type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
	Created      string `json:"created,omitempty"`
	Author       string `json:"author,omitempty"`
	Config       struct {
		User         string            `json:"User,omitempty"`
		Env          []string          `json:"Env,omitempty"`
		Entrypoint   []string          `json:"Entrypoint,omitempty"`
		Cmd          []string          `json:"Cmd,omitempty"`
		WorkingDir   string            `json:"WorkingDir,omitempty"`
		Labels       map[string]string `json:"Labels,omitempty"`
		ExposedPorts map[string]any    `json:"ExposedPorts,omitempty"`
	} `json:"config"`
	History []struct {
		Created    string `json:"created,omitempty"`
		CreatedBy  string `json:"created_by,omitempty"`
		Comment    string `json:"comment,omitempty"`
		EmptyLayer bool   `json:"empty_layer,omitempty"`
	} `json:"history,omitempty"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// referrersIndex is the OCI 1.1 response body for the referrers API.
type referrersIndex struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []descriptor `json:"manifests"`
}
