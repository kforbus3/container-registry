package sbom

import (
	"encoding/json"
	"path"
	"strings"
)

// Language ecosystems are discovered from the metadata each package manager
// leaves on disk when it installs something, rather than from lock files: what
// is actually present in the image is what belongs in its bill of materials.

// ---------------------------------------------------------------- npm

// isNPMManifest matches the package.json of an installed npm package.
//
// Installed packages live at <prefix>/node_modules/<name>/package.json, or
// <prefix>/node_modules/@scope/<name>/package.json when scoped, and nest
// arbitrarily deep. The project's own package.json — one that is not inside a
// node_modules directory — is deliberately not matched: it describes intent
// rather than what is installed.
func isNPMManifest(name string) bool {
	if path.Base(name) != "package.json" {
		return false
	}
	dir := path.Dir(name)
	parent := path.Base(dir)
	grandparent := path.Base(path.Dir(dir))

	switch {
	case parent == "node_modules":
		return false // node_modules/package.json is not a package
	case grandparent == "node_modules":
		// node_modules/<name>/package.json — skip npm's own bookkeeping.
		return !strings.HasPrefix(parent, ".")
	case strings.HasPrefix(grandparent, "@"):
		// node_modules/@scope/<name>/package.json
		return path.Base(path.Dir(path.Dir(dir))) == "node_modules"
	}
	return false
}

// npmManifest is the subset of package.json that identifies a package.
type npmManifest struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	License json.RawMessage `json:"license"`
	// Deprecated but still present in older packages.
	Licenses json.RawMessage `json:"licenses"`
	Private  bool            `json:"private"`
}

func parseNPM(filePath string, content []byte) []pkg {
	var m npmManifest
	if err := json.Unmarshal(content, &m); err != nil {
		return nil
	}
	if m.Name == "" || m.Version == "" {
		// Without both, the entry cannot be matched against an advisory.
		return nil
	}
	return []pkg{{
		Name:      m.Name,
		Version:   m.Version,
		License:   npmLicense(m),
		Ecosystem: "npm",
		Source:    "package.json",
		Path:      filePath,
	}}
}

// npmLicense normalises the several shapes the license field has taken:
// a string, an object with a "type", or an array of either.
func npmLicense(m npmManifest) string {
	if s := licenseFromJSON(m.License); s != "" {
		return s
	}
	return licenseFromJSON(m.Licenses)
}

func licenseFromJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Type != "" {
		return obj.Type
	}
	var list []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &list) == nil {
		var parts []string
		for _, l := range list {
			if l.Type != "" {
				parts = append(parts, l.Type)
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

// ---------------------------------------------------------------- python

// isPythonMetadata matches the metadata file an installed Python distribution
// leaves behind: METADATA for the modern wheel layout, PKG-INFO for the older
// egg layout.
func isPythonMetadata(name string) bool {
	base := path.Base(name)
	dir := path.Base(path.Dir(name))
	switch base {
	case "METADATA":
		return strings.HasSuffix(dir, ".dist-info")
	case "PKG-INFO":
		return strings.HasSuffix(dir, ".egg-info") || strings.HasSuffix(dir, ".dist-info")
	}
	return false
}

// parsePython reads a PEP 566 metadata file, which is a mail-style header
// block: field names at the start of a line, continuations indented.
func parsePython(filePath string, content []byte) []pkg {
	var p pkg
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			break // the headers end at the first blank line; a description follows
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation of the previous field
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch key {
		case "Name":
			p.Name = strings.TrimSpace(value)
		case "Version":
			p.Version = strings.TrimSpace(value)
		case "License":
			if p.License == "" {
				p.License = strings.TrimSpace(value)
			}
		case "License-Expression":
			// PEP 639 supersedes the free-text License field.
			p.License = strings.TrimSpace(value)
		case "Classifier":
			// "License :: OSI Approved :: MIT License" is the only license
			// signal in many older packages.
			if p.License == "" && strings.HasPrefix(value, "License :: ") {
				parts := strings.Split(value, " :: ")
				p.License = strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}
	if p.Name == "" || p.Version == "" {
		return nil
	}
	p.Ecosystem = "pypi"
	p.Source = path.Base(filePath)
	p.Path = filePath
	// Package URLs use the normalised distribution name.
	p.Name = normalisePythonName(p.Name)
	return []pkg{p}
}

// normalisePythonName applies PEP 503 normalisation, which is what advisory
// databases key on: lowercase, with runs of -, _ and . collapsed to a hyphen.
func normalisePythonName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	lastDash := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return strings.Trim(b.String(), "-")
}
