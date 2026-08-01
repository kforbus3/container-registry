package vuln

import (
	"strings"
)

// Match is the verdict on whether one advisory really affects one installed
// package, and if so what fixes it.
type Match struct {
	Applies bool
	Fixed   string
}

// AppliesTo decides whether an advisory affects the given package.
//
// Most ecosystems need no such check: OSV's query endpoint already compares
// versions for them, and a returned advisory is a real hit. Red Hat is the
// exception. Its advisories are published under an ecosystem that is not split
// by release, so a query matches every RHEL major version at once and reports,
// for instance, a RHEL 9 advisory against a RHEL 8 image. Those are filtered
// out here by comparing against the advisory's own affected ranges.
//
// release is the distribution major version taken from the image, or "" when
// it is unknown, in which case nothing is filtered — an unverifiable finding is
// still reported rather than silently dropped.
func (a *Advisory) AppliesTo(pkgName, version, release string) Match {
	var (
		sawPackage bool
		bestFix    string
	)
	for _, aff := range a.Affected {
		if !samePackage(aff.Package.Name, pkgName) {
			continue
		}
		// The ecosystem string looks like "Red Hat:enterprise_linux:8::appstream".
		// Only entries for this image's release can say anything about it.
		if release != "" && !ecosystemMatchesRelease(aff.Package.Ecosystem, release) {
			continue
		}
		sawPackage = true

		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				// Installed at or above the fix means already patched.
				if CompareEVR(version, e.Fixed) >= 0 {
					return Match{Applies: false}
				}
				if bestFix == "" || CompareEVR(e.Fixed, bestFix) < 0 {
					bestFix = e.Fixed
				}
			}
		}
	}
	if !sawPackage {
		// The advisory came back for this package but names no affected entry
		// for this release: it belongs to a different operating system version.
		return Match{Applies: false}
	}
	return Match{Applies: true, Fixed: strings.TrimPrefix(bestFix, "0:")}
}

// samePackage compares package names, tolerating the source-package and
// debuginfo variants Red Hat lists alongside the binary package.
func samePackage(advisoryName, installed string) bool {
	if advisoryName == installed {
		return true
	}
	// "curl-debuginfo" and "curl-debugsource" describe the same source but are
	// not what is installed, so they must not be treated as a match.
	return false
}

// ecosystemMatchesRelease reports whether an OSV ecosystem string refers to the
// given distribution major version.
func ecosystemMatchesRelease(ecosystem, release string) bool {
	if ecosystem == "" || release == "" {
		return true
	}
	// "Red Hat:enterprise_linux:8::appstream" -> the segment after the product.
	for _, part := range strings.Split(ecosystem, ":") {
		if part == release {
			return true
		}
	}
	return false
}

// needsRangeCheck reports whether an ecosystem's results have to be verified
// against the advisory's affected ranges rather than trusted as returned.
func needsRangeCheck(ecosystem string) bool {
	return strings.HasPrefix(ecosystem, "Red Hat")
}

// majorOf extracts the major version from a distro string such as "rhel-8.10".
func majorOf(namespace string) string {
	_, version, ok := strings.Cut(namespace, "-")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(version, '.'); i >= 0 {
		return version[:i]
	}
	return version
}
