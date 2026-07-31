package sbom

import (
	"bytes"
	"debug/buildinfo"
	"strings"
)

// parseAPK reads an Alpine /lib/apk/db/installed database.
//
// The format is a sequence of records separated by blank lines, each a set of
// single-letter keyed lines: P (package), V (version), A (architecture),
// L (license), o (origin).
func parseAPK(db []byte) []pkg {
	var out []pkg
	var cur pkg
	flush := func() {
		if cur.Name != "" {
			cur.Ecosystem = "apk"
			cur.Source = "lib/apk/db/installed"
			out = append(out, cur)
		}
		cur = pkg{}
	}

	for _, raw := range strings.Split(string(db), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || len(key) != 1 {
			continue
		}
		switch key {
		case "P":
			cur.Name = value
		case "V":
			cur.Version = value
		case "A":
			cur.Arch = value
		case "L":
			cur.License = value
		}
	}
	flush()
	return out
}

// parseDpkg reads a Debian/Ubuntu /var/lib/dpkg/status file.
//
// Records are RFC822-style stanzas separated by blank lines. Only packages
// whose Status marks them actually installed are reported: the file also
// retains entries for packages that were removed but left config behind.
func parseDpkg(db []byte) []pkg {
	var out []pkg
	var cur pkg
	installed := false

	flush := func() {
		if cur.Name != "" && installed {
			cur.Ecosystem = "deb"
			cur.Source = "var/lib/dpkg/status"
			out = append(out, cur)
		}
		cur = pkg{}
		installed = false
	}

	for _, raw := range strings.Split(string(db), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			flush()
			continue
		}
		// Continuation lines belong to the previous field and carry nothing
		// this scanner needs.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			// A field with an empty value still terminates nothing.
			key = strings.TrimSuffix(line, ":")
			value = ""
		}
		switch key {
		case "Package":
			cur.Name = value
		case "Version":
			cur.Version = value
		case "Architecture":
			cur.Arch = value
		case "Status":
			// e.g. "install ok installed"
			installed = strings.HasSuffix(value, " installed")
		}
	}
	flush()
	return out
}

// parseGoBinary extracts module versions embedded in a Go executable. Images
// built FROM scratch or distroless carry no package database at all, so this is
// often the only source of component data for them.
func parseGoBinary(path string, content []byte) []pkg {
	info, err := buildinfo.Read(bytes.NewReader(content))
	if err != nil {
		return nil
	}
	out := make([]pkg, 0, len(info.Deps)+2)

	if info.Main.Path != "" {
		out = append(out, pkg{
			Name:      info.Main.Path,
			Version:   moduleVersion(info.Main.Version),
			Ecosystem: "golang",
			Source:    "go build info",
			Path:      path,
		})
	}
	// The toolchain itself is a real component for vulnerability purposes.
	if info.GoVersion != "" {
		out = append(out, pkg{
			Name:      "stdlib",
			Version:   strings.TrimPrefix(info.GoVersion, "go"),
			Ecosystem: "golang",
			Source:    "go build info",
			Path:      path,
		})
	}
	for _, d := range info.Deps {
		if d == nil || d.Path == "" {
			continue
		}
		// A replaced module reports the replacement's identity.
		mod := d
		if d.Replace != nil && d.Replace.Path != "" {
			mod = d.Replace
		}
		out = append(out, pkg{
			Name:      mod.Path,
			Version:   moduleVersion(mod.Version),
			Ecosystem: "golang",
			Source:    "go build info",
			Path:      path,
		})
	}
	return out
}

// moduleVersion normalises the placeholder Go uses for a main module built
// outside a tagged release.
func moduleVersion(v string) string {
	if v == "" || v == "(devel)" {
		return ""
	}
	return v
}
