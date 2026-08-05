package sbom

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"path"
	"regexp"
	"strings"
)

// Language ecosystems beyond npm and PyPI.
//
// Each is found the way its package manager actually records an installation,
// not by guessing from file names: a Java archive carries the coordinates Maven
// wrote into it, a gem carries a gemspec, .NET writes a dependency manifest
// next to the assembly, and Composer keeps an installed.json. Guessing from a
// file name gets the version wrong often enough to be worse than not reporting.

// ---------------------------------------------------------------- Java

// isJavaArchive matches the archive types that carry Maven coordinates.
func isJavaArchive(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jar", ".war", ".ear", ".hpi", ".jpi":
		return true
	}
	return false
}

var pomCoordinates = regexp.MustCompile(`(?m)^\s*(groupId|artifactId|version)\s*=\s*(.+?)\s*$`)

// parseJavaArchive reads coordinates out of a jar, war or ear.
//
// Maven writes META-INF/maven/<group>/<artifact>/pom.properties into the
// archives it builds, which is the only place the group id is recorded
// exactly. Where that is missing the OSGi and Implementation headers in the
// manifest are used, and a name parsed from the file name is the last resort.
func parseJavaArchive(archivePath string, content []byte) []pkg {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil
	}
	var out []pkg
	seen := map[string]bool{}

	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "META-INF/maven/") || path.Base(f.Name) != "pom.properties" {
			continue
		}
		body, err := readZipEntry(f, 64<<10)
		if err != nil {
			continue
		}
		var group, artifact, version string
		for _, m := range pomCoordinates.FindAllStringSubmatch(string(body), -1) {
			switch m[1] {
			case "groupId":
				group = m[2]
			case "artifactId":
				artifact = m[2]
			case "version":
				version = m[2]
			}
		}
		if artifact == "" || version == "" {
			continue
		}
		name := artifact
		if group != "" {
			name = group + ":" + artifact
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, pkg{
			Name: name, Version: version, Ecosystem: "maven",
			Source: "pom.properties", Path: archivePath,
		})
	}
	if len(out) > 0 {
		return out
	}

	// No Maven metadata: fall back to the manifest, then the file name.
	for _, f := range zr.File {
		if f.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		body, err := readZipEntry(f, 256<<10)
		if err != nil {
			break
		}
		if p, ok := javaFromManifest(archivePath, body); ok {
			return []pkg{p}
		}
		break
	}
	if p, ok := javaFromFileName(archivePath); ok {
		return []pkg{p}
	}
	return nil
}

// javaFromManifest reads an identifier out of a jar manifest.
//
// Field order matters. Bundle-SymbolicName and Automatic-Module-Name are
// identifiers by definition; Implementation-Title is frequently prose -- ASM
// sets it to "ASM, a very small and fast Java bytecode manipulation framework"
// -- and a name like that cannot be part of a package URL and would never match
// an advisory. It is used only when it actually looks like an identifier.
func javaFromManifest(archivePath string, body []byte) (pkg, bool) {
	fields := parseManifestFields(body)
	version := firstNonEmpty(
		fields["Bundle-Version"],
		fields["Implementation-Version"],
		fields["Specification-Version"],
	)
	if version == "" {
		return pkg{}, false
	}
	for _, key := range []string{"Bundle-SymbolicName", "Automatic-Module-Name", "Implementation-Title"} {
		name := fields[key]
		// A symbolic name can carry directives after a semicolon.
		if i := strings.IndexByte(name, ';'); i > 0 {
			name = name[:i]
		}
		if !isIdentifierLike(name) {
			continue
		}
		return pkg{
			Name: name, Version: version, Ecosystem: "maven",
			Source: "MANIFEST.MF", Path: archivePath,
		}, true
	}
	return pkg{}, false
}

// parseManifestFields reads a jar manifest, joining the continuation lines the
// format requires.
//
// A manifest wraps every value at 72 bytes and continues it on the next line
// with a single leading space. Reading line by line without rejoining silently
// truncates any value past that length, which is how a name arrived here cut
// off mid-word.
func parseManifestFields(body []byte) map[string]string {
	fields := map[string]string{}
	var key string
	var value strings.Builder
	flush := func() {
		if key != "" {
			fields[key] = value.String()
		}
		key, value = "", strings.Builder{}
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, " ") && key != "" {
			value.WriteString(strings.TrimPrefix(line, " "))
			continue
		}
		flush()
		if k, v, ok := strings.Cut(line, ": "); ok {
			key = strings.TrimSpace(k)
			value.WriteString(strings.TrimSpace(v))
		}
	}
	flush()
	return fields
}

// isIdentifierLike rejects prose. A package URL cannot carry spaces or commas,
// so a "name" containing them is a description that happened to be in a field
// this reads, and emitting it would produce a purl that matches nothing.
func isIdentifierLike(name string) bool {
	if name == "" || len(name) > 200 {
		return false
	}
	return !strings.ContainsAny(name, " ,()[]{}\"'\\")
}

var jarFileName = regexp.MustCompile(`^(.+?)-(\d[\w.\-]*)$`)

// javaFromFileName is the last resort: name-version.jar.
func javaFromFileName(archivePath string) (pkg, bool) {
	base := path.Base(archivePath)
	base = strings.TrimSuffix(base, path.Ext(base))
	m := jarFileName.FindStringSubmatch(base)
	if m == nil {
		return pkg{}, false
	}
	if !isIdentifierLike(m[1]) {
		return pkg{}, false
	}
	return pkg{
		Name: m[1], Version: m[2], Ecosystem: "maven",
		Source: "file name", Path: archivePath,
	}, true
}

func readZipEntry(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, max))
}

// ---------------------------------------------------------------- Ruby

// isGemspec matches an installed gem's specification.
//
// RubyGems records every installed gem as a .gemspec under specifications/,
// including the default gems shipped with the interpreter under
// specifications/default/.
func isGemspec(name string) bool {
	if path.Ext(name) != ".gemspec" {
		return false
	}
	dir := path.Dir(name)
	return path.Base(dir) == "specifications" || path.Base(path.Dir(dir)) == "specifications"
}

var (
	gemName    = regexp.MustCompile(`\.name\s*=\s*["']([^"']+)["']`)
	gemVersion = regexp.MustCompile(`\.version\s*=\s*["']([^"']+)["']`)
	gemLicense = regexp.MustCompile(`\.licenses\s*=\s*\[["']([^"']+)["']`)
)

// parseGemspec reads a gem's name and version.
//
// A gemspec is executable Ruby rather than data, so this reads the two
// assignments that are conventionally literals. Anything computed at load time
// is not recoverable without running the file, which is not worth doing to
// describe an image.
func parseGemspec(specPath string, content []byte) []pkg {
	body := string(content)
	n := gemName.FindStringSubmatch(body)
	v := gemVersion.FindStringSubmatch(body)
	if n == nil || v == nil {
		// Fall back to the file name, which RubyGems writes as name-version.
		base := strings.TrimSuffix(path.Base(specPath), ".gemspec")
		if i := strings.LastIndexByte(base, '-'); i > 0 {
			return []pkg{{
				Name: base[:i], Version: base[i+1:], Ecosystem: "gem",
				Source: "gemspec file name", Path: specPath,
			}}
		}
		return nil
	}
	p := pkg{
		Name: n[1], Version: v[1], Ecosystem: "gem",
		Source: "gemspec", Path: specPath,
	}
	if l := gemLicense.FindStringSubmatch(body); l != nil {
		p.License = l[1]
	}
	return []pkg{p}
}

// ---------------------------------------------------------------- .NET

// isDotNetDeps matches the dependency manifest published beside an assembly.
func isDotNetDeps(name string) bool {
	return strings.HasSuffix(name, ".deps.json")
}

// parseDotNetDeps reads the libraries a published .NET application carries.
func parseDotNetDeps(depsPath string, content []byte) []pkg {
	var doc struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil
	}
	out := make([]pkg, 0, len(doc.Libraries))
	for key, lib := range doc.Libraries {
		name, version, ok := strings.Cut(key, "/")
		if !ok || name == "" || version == "" {
			continue
		}
		// "project" entries are the application's own assemblies rather than
		// dependencies, and have no package to match against.
		if lib.Type == "project" {
			continue
		}
		out = append(out, pkg{
			Name: name, Version: version, Ecosystem: "nuget",
			Source: "deps.json", Path: depsPath,
		})
	}
	return out
}

// ---------------------------------------------------------------- PHP

// isComposerInstalled matches Composer's record of what it installed.
func isComposerInstalled(name string) bool {
	return strings.HasSuffix(name, "vendor/composer/installed.json")
}

// parseComposerInstalled reads Composer's installed package list, which has had
// two shapes: a bare array in Composer 1 and an object with "packages" in
// Composer 2.
func parseComposerInstalled(installedPath string, content []byte) []pkg {
	type entry struct {
		Name    string   `json:"name"`
		Version string   `json:"version"`
		License []string `json:"license"`
	}
	var wrapped struct {
		Packages []entry `json:"packages"`
	}
	var entries []entry
	if err := json.Unmarshal(content, &wrapped); err == nil && len(wrapped.Packages) > 0 {
		entries = wrapped.Packages
	} else {
		var bare []entry
		if err := json.Unmarshal(content, &bare); err != nil {
			return nil
		}
		entries = bare
	}
	out := make([]pkg, 0, len(entries))
	for _, e := range entries {
		if e.Name == "" || e.Version == "" {
			continue
		}
		p := pkg{
			Name: e.Name, Version: strings.TrimPrefix(e.Version, "v"),
			Ecosystem: "composer", Source: "installed.json", Path: installedPath,
		}
		if len(e.License) > 0 {
			p.License = e.License[0]
		}
		out = append(out, p)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------- runtimes

// Language runtimes compiled into an image rather than installed as packages.
//
// The official python and node images build their interpreter from source, so
// no package database mentions it and its CVEs would go unreported. These are
// found by looking for a version string at a path that already tells us which
// runtime it is -- the path supplies the identity, the content only the
// version, so a loose pattern cannot mislabel something else.

var (
	libPythonPath = regexp.MustCompile(`(^|/)libpython(\d+\.\d+)\.so`)
	nodeVersion   = regexp.MustCompile(`node\.js/v(\d+\.\d+\.\d+)`)
)

// runtimeProbe describes how to identify one runtime from a file.
type runtimeProbe struct {
	name    string
	pattern *regexp.Regexp
}

// runtimeProbeFor reports how to read a version out of a file, if it is a
// runtime worth identifying.
func runtimeProbeFor(name string) (runtimeProbe, bool) {
	if m := libPythonPath.FindStringSubmatch(name); m != nil {
		// The path fixes the major.minor, so the pattern only has to find the
		// patch level belonging to it.
		return runtimeProbe{
			name:    "python",
			pattern: regexp.MustCompile(regexp.QuoteMeta(m[2]) + `\.\d+`),
		}, true
	}
	if path.Base(name) == "node" && strings.Contains(name, "bin/") {
		return runtimeProbe{name: "node", pattern: nodeVersion}, true
	}
	return runtimeProbe{}, false
}

// scanRuntime streams a file looking for its version, so a 100 MiB interpreter
// is never held in memory to read a dozen characters out of it.
func scanRuntime(probe runtimeProbe, filePath string, r io.Reader, max int64) (pkg, bool) {
	const window = 1 << 20
	buf := make([]byte, window)
	// Carry the tail of each chunk so a match spanning a boundary is still seen.
	const overlap = 64
	var carry []byte
	var read int64

	for read < max {
		n, err := r.Read(buf)
		if n > 0 {
			read += int64(n)
			hay := append(carry, buf[:n]...)
			if m := probe.pattern.FindSubmatch(hay); m != nil {
				v := string(m[len(m)-1])
				return pkg{
					Name: probe.name, Version: v, Ecosystem: probe.name,
					Source: "runtime binary", Path: filePath,
				}, true
			}
			if len(hay) > overlap {
				carry = append(carry[:0], hay[len(hay)-overlap:]...)
			} else {
				carry = append(carry[:0], hay...)
			}
		}
		if err != nil {
			break
		}
	}
	return pkg{}, false
}
