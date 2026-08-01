package vuln

import (
	"strings"
)

// OSV indexes operating-system packages by its own ecosystem names rather than
// by package URL: a purl query for an Alpine or Debian package returns nothing
// at all, even when advisories exist. Language ecosystems (npm, PyPI, Go) are
// the opposite and match on purl directly.
//
// So each component is turned into whichever query shape actually finds it.

// Query is one lookup against the advisory database, in whichever of the two
// forms OSV indexes that ecosystem under.
type Query struct {
	// PURL is set for language ecosystems.
	PURL string
	// Name, Ecosystem and Version are set for operating-system packages.
	Name      string
	Ecosystem string
	Version   string
}

// purlParts is a package URL split into its components.
type purlParts struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	// Epoch is the RPM epoch qualifier. It is carried separately in the purl
	// but is the most significant field when comparing RPM versions, so
	// dropping it makes a patched package look vulnerable.
	Epoch string
}

// parsePURL splits a package URL. Scoped npm names keep their namespace joined
// to the name, since "@babel/core" is one package identifier.
func parsePURL(purl string) (purlParts, bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return purlParts{}, false
	}
	rest := purl[len("pkg:"):]
	qualifiers := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, qualifiers = rest[:i], rest[i+1:]
	}
	typ, rest, ok := strings.Cut(rest, "/")
	if !ok || typ == "" {
		return purlParts{}, false
	}

	// Split the version off the *last* '@'. A scoped npm package starts with
	// one — "@babel/core@7.24.0" — so splitting on the first would take the
	// scope for the version and leave an empty name.
	name, version := rest, ""
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		name, version = rest[:i], rest[i+1:]
	}

	var namespace string
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		namespace, name = name[:i], name[i+1:]
	}
	// A bare npm scope with nothing after it — "@babel" — names no package.
	if name == "" || strings.HasPrefix(name, "@") {
		return purlParts{}, false
	}
	out := purlParts{Type: typ, Namespace: namespace, Name: name, Version: version}
	for _, q := range strings.Split(qualifiers, "&") {
		if k, v, ok := strings.Cut(q, "="); ok && k == "epoch" {
			out.Epoch = v
		}
	}
	return out, true
}

// EVRFromPURL renders the full epoch:version-release string for an RPM package
// URL, which is what an advisory's fixed versions are expressed in.
func EVRFromPURL(purl string) string {
	p, ok := parsePURL(purl)
	if !ok {
		return ""
	}
	if p.Epoch != "" {
		return p.Epoch + ":" + p.Version
	}
	return p.Version
}

// QueryFor builds the lookup for a component's package URL, reporting false
// when the component cannot be matched against anything.
func QueryFor(purl string) (Query, bool) {
	p, ok := parsePURL(purl)
	if !ok {
		return Query{}, false
	}
	switch p.Type {
	case "apk", "deb", "rpm":
		eco := osvEcosystem(p.Type, p.Namespace)
		if eco == "" || p.Version == "" {
			return Query{}, false
		}
		return Query{Name: p.Name, Ecosystem: eco, Version: p.Version}, true

	case "npm", "pypi", "golang", "cargo", "maven", "gem", "nuget", "composer":
		// These are indexed by purl and match directly.
		return Query{PURL: purl}, true
	}
	return Query{}, false
}

// osvEcosystem maps a distribution to the ecosystem name OSV publishes under.
//
// The namespace comes from the SBOM, where it is "<id>-<version_id>" taken from
// os-release — "alpine-3.16.2", "debian-12", "rocky-9.3", "rhel-8.10". Each
// distribution wants a different slice of that, and the formats were determined
// against the live API rather than guessed:
//
//	Alpine        Alpine:v3.16   version required; a bare "Alpine" matches nothing
//	Debian        Debian:12      major only
//	Ubuntu        Ubuntu:22.04   major.minor
//	Rocky, Alma   Rocky Linux:9  major only
//	Red Hat       Red Hat        no version at all
func osvEcosystem(purlType, namespace string) string {
	id, version := namespace, ""
	if i := strings.IndexByte(namespace, '-'); i >= 0 {
		id, version = namespace[:i], namespace[i+1:]
	}
	id = strings.ToLower(id)

	switch id {
	case "alpine":
		// Advisories are tracked per release branch, so major.minor.
		if mm := majorMinor(version); mm != "" {
			return "Alpine:v" + mm
		}
		return ""
	case "debian":
		if maj := major(version); maj != "" {
			return "Debian:" + maj
		}
		return ""
	case "ubuntu":
		if mm := majorMinor(version); mm != "" {
			return "Ubuntu:" + mm
		}
		return ""
	case "rocky":
		if maj := major(version); maj != "" {
			return "Rocky Linux:" + maj
		}
		return ""
	case "almalinux", "alma":
		if maj := major(version); maj != "" {
			return "AlmaLinux:" + maj
		}
		return ""
	case "rhel", "redhat", "centos":
		// Red Hat's OSV feed is not split by release.
		return "Red Hat"
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "openSUSE"
	case "sles", "suse":
		return "SUSE"
	case "wolfi":
		return "Wolfi"
	case "chainguard":
		return "Chainguard"
	case "mageia":
		return "Mageia"
	case "photon":
		return "Photon OS"
	}
	// An unmapped distribution is reported as unqueryable rather than guessed
	// at, so it shows up as "not checked" instead of a false all-clear.
	if purlType == "rpm" {
		return "Red Hat"
	}
	return ""
}

func major(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

func majorMinor(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + "." + parts[1]
}
