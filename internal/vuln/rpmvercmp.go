package vuln

import (
	"strconv"
	"strings"
)

// Red Hat publishes its advisories to OSV under an ecosystem that is not split
// by release — a query for "Red Hat" matches every RHEL major version at once.
// Left alone that reports RHEL 9 advisories against RHEL 8 images: real
// advisory, wrong operating system, and no usable fix version.
//
// So Red Hat findings are checked here against the advisory's own affected
// ranges before being reported, which needs RPM's version comparison.

// CompareRPMVersions implements rpmvercmp, returning -1, 0 or 1.
//
// The algorithm walks both strings in parallel, comparing runs of digits
// numerically and runs of letters lexically, with two special characters:
// '~' sorts before everything (used for pre-releases) and '^' sorts after.
func CompareRPMVersions(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Separators are not significant beyond ending a segment.
		for i < len(a) && !isAlnumTilde(a[i]) {
			i++
		}
		for j < len(b) && !isAlnumTilde(b[j]) {
			j++
		}

		// A tilde sorts before anything else, including the empty string.
		if i < len(a) && a[i] == '~' || j < len(b) && b[j] == '~' {
			aTilde := i < len(a) && a[i] == '~'
			bTilde := j < len(b) && b[j] == '~'
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}
		// A caret sorts after everything, except that it loses to a longer
		// string that has more segments to come.
		if i < len(a) && a[i] == '^' || j < len(b) && b[j] == '^' {
			aCaret := i < len(a) && a[i] == '^'
			bCaret := j < len(b) && b[j] == '^'
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case !aCaret:
				return 1
			case !bCaret:
				return -1
			}
			i++
			j++
			continue
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		startA, startB := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}

		segA, segB := a[startA:i], b[startB:j]
		// One side ran out of this segment type: a numeric segment beats an
		// alphabetic one, so the side that still has digits is newer.
		if segB == "" {
			if isNum {
				return 1
			}
			return -1
		}
		if segA == "" {
			if isNum {
				return -1
			}
			return 1
		}

		if isNum {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			if len(segA) != len(segB) {
				if len(segA) > len(segB) {
					return 1
				}
				return -1
			}
		}
		if segA != segB {
			if segA > segB {
				return 1
			}
			return -1
		}
	}

	// Whatever is left over decides it.
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		// A trailing tilde still sorts before the shorter string.
		if a[i] == '~' {
			return -1
		}
		return 1
	default:
		if b[j] == '~' {
			return 1
		}
		return -1
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnumTilde(c byte) bool {
	return isDigit(c) || isAlpha(c) || c == '~' || c == '^'
}

// evr is an RPM epoch-version-release triple.
type evr struct {
	epoch   int
	version string
	release string
}

// parseEVR splits "1:1.1.1k-12.el8_9" into its parts. A missing epoch is zero,
// which is how RPM treats it.
func parseEVR(s string) evr {
	out := evr{}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if n, err := strconv.Atoi(s[:i]); err == nil {
			out.epoch = n
		}
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		out.version, out.release = s[:i], s[i+1:]
	} else {
		out.version = s
	}
	return out
}

// CompareEVR compares two full epoch-version-release strings.
func CompareEVR(a, b string) int {
	x, y := parseEVR(a), parseEVR(b)
	if x.epoch != y.epoch {
		if x.epoch > y.epoch {
			return 1
		}
		return -1
	}
	if c := CompareRPMVersions(x.version, y.version); c != 0 {
		return c
	}
	return CompareRPMVersions(x.release, y.release)
}
