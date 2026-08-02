// Package sbom generates a Software Bill of Materials for images as they are
// pushed, and publishes it back into the registry as an OCI referrer artifact
// attached to the image it describes.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// MediaType is the artifactType used for the published SBOM. It is the media
// type CycloneDX registers for its JSON encoding, so any OCI-aware scanner can
// find these artifacts through the referrers API without knowing about this
// registry specifically.
const MediaType = "application/vnd.cyclonedx+json"

// SpecVersion is the CycloneDX schema version emitted.
const SpecVersion = "1.5"

// Document is a CycloneDX 1.5 bill of materials.
type Document struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     []Tool     `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Component is one entry in the bill of materials.
type Component struct {
	Type        string     `json:"type"`
	BOMRef      string     `json:"bom-ref,omitempty"`
	Name        string     `json:"name"`
	Version     string     `json:"version,omitempty"`
	Description string     `json:"description,omitempty"`
	PURL        string     `json:"purl,omitempty"`
	Licenses    []License  `json:"licenses,omitempty"`
	Properties  []Property `json:"properties,omitempty"`
	Hashes      []Hash     `json:"hashes,omitempty"`
}

type License struct {
	License LicenseChoice `json:"license"`
}

type LicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// pkg is the internal, format-neutral result of a scanner.
type pkg struct {
	Name      string
	Version   string
	Arch      string
	Epoch     string // RPM only, and only when non-zero
	License   string
	Ecosystem string // apk | deb | rpm | npm | pypi | golang | maven | gem | nuget | composer
	Source    string // the file the package was discovered in
	Path      string // where in the image the file lived
}

// purl renders a package URL, the identifier vulnerability scanners match on.
func (p pkg) purl(distro string) string {
	switch p.Ecosystem {
	case "apk":
		q := ""
		if p.Arch != "" {
			q = "?arch=" + p.Arch
		}
		name := distro
		if name == "" {
			name = "alpine"
		}
		return fmt.Sprintf("pkg:apk/%s/%s@%s%s", name, p.Name, p.Version, q)
	case "deb":
		q := ""
		if p.Arch != "" {
			q = "?arch=" + p.Arch
		}
		name := distro
		if name == "" {
			name = "debian"
		}
		return fmt.Sprintf("pkg:deb/%s/%s@%s%s", name, p.Name, p.Version, q)
	case "rpm":
		name := distro
		if name == "" {
			name = "redhat"
		}
		var qualifiers []string
		if p.Arch != "" {
			qualifiers = append(qualifiers, "arch="+p.Arch)
		}
		if p.Epoch != "" {
			qualifiers = append(qualifiers, "epoch="+p.Epoch)
		}
		q := ""
		if len(qualifiers) > 0 {
			q = "?" + strings.Join(qualifiers, "&")
		}
		return fmt.Sprintf("pkg:rpm/%s/%s@%s%s", name, p.Name, p.Version, q)
	case "npm":
		// A scoped name already carries its own slash, which purl keeps.
		return fmt.Sprintf("pkg:npm/%s@%s", p.Name, p.Version)
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", p.Name, p.Version)
	case "golang":
		return fmt.Sprintf("pkg:golang/%s@%s", p.Name, p.Version)
	case "maven":
		// Maven coordinates are group:artifact; purl separates them with a
		// slash, and an artifact with no group keeps the bare name.
		if g, a, ok := strings.Cut(p.Name, ":"); ok {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", g, a, p.Version)
		}
		return fmt.Sprintf("pkg:maven/%s@%s", p.Name, p.Version)
	case "gem":
		return fmt.Sprintf("pkg:gem/%s@%s", p.Name, p.Version)
	case "nuget":
		return fmt.Sprintf("pkg:nuget/%s@%s", p.Name, p.Version)
	case "composer":
		return fmt.Sprintf("pkg:composer/%s@%s", p.Name, p.Version)
	case "python", "node":
		// A runtime built into the image rather than installed as a package.
		// Both are indexed by OSV under these names.
		return fmt.Sprintf("pkg:generic/%s@%s", p.Name, p.Version)
	}
	return ""
}

// bomRef must be unique within a document.
func (p pkg) bomRef() string {
	sum := sha256.Sum256([]byte(p.Ecosystem + "|" + p.Name + "|" + p.Version + "|" + p.Path))
	return p.Ecosystem + ":" + p.Name + ":" + hex.EncodeToString(sum[:])[:12]
}

// toComponents converts scanner output into a stable, de-duplicated component
// list. Ordering is deterministic so re-scanning identical content yields a
// byte-identical document, which in turn yields the same digest.
func toComponents(pkgs []pkg, distro string) []Component {
	seen := map[string]bool{}
	out := make([]Component, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		key := p.Ecosystem + "|" + p.Name + "|" + p.Version + "|" + p.Path
		if seen[key] {
			continue
		}
		seen[key] = true

		c := Component{
			Type:    "library",
			BOMRef:  p.bomRef(),
			Name:    p.Name,
			Version: p.Version,
			PURL:    p.purl(distro),
		}
		if p.License != "" {
			// A license string may be an SPDX expression; record it by name so
			// no claim of SPDX-ID validity is made that was not verified.
			c.Licenses = []License{{License: LicenseChoice{Name: p.License}}}
		}
		if p.Arch != "" {
			c.Properties = append(c.Properties, Property{Name: "registry:arch", Value: p.Arch})
		}
		if p.Epoch != "" {
			c.Properties = append(c.Properties, Property{Name: "registry:epoch", Value: p.Epoch})
		}
		c.Properties = append(c.Properties, Property{Name: "registry:ecosystem", Value: p.Ecosystem})
		if p.Source != "" {
			c.Properties = append(c.Properties, Property{Name: "registry:foundIn", Value: p.Source})
		}
		if p.Path != "" {
			c.Properties = append(c.Properties, Property{Name: "registry:path", Value: p.Path})
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].BOMRef < out[j].BOMRef
	})
	return out
}

// distroFrom derives a package-URL namespace from an os-release file.
func distroFrom(osRelease string) string {
	id, versionID := "", ""
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			versionID = v
		}
	}
	if id == "" {
		return ""
	}
	if versionID == "" {
		return id
	}
	return id + "-" + versionID
}
