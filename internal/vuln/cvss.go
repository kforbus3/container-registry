package vuln

import (
	"math"
	"strings"
)

// Severity buckets, ordered so they can be compared.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// SeverityRank orders severities for sorting; higher is worse.
func SeverityRank(s string) int {
	switch strings.ToUpper(s) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// SeverityForScore buckets a CVSS base score using the qualitative rating scale
// defined by the CVSS v3.1 specification.
func SeverityForScore(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	}
	return SeverityUnknown
}

// metric weights from the CVSS v3.1 specification, section 7.
var (
	attackVector = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	attackCplx   = map[string]float64{"L": 0.77, "H": 0.44}
	userInteract = map[string]float64{"N": 0.85, "R": 0.62}
	impactWeight = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	// Privileges Required is weighted differently when the vulnerability can
	// affect resources beyond its own security scope.
	privRequiredUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	privRequiredChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// ScoreCVSSVector computes the CVSS v3.x base score from a vector string such
// as "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H".
//
// The score is computed rather than taken from a vendor's own rating because
// advisories disagree: the same CVE is routinely labelled differently by
// different databases, and only the vector is common to all of them. Returns
// ok=false for anything that is not a v3 vector, including v4, which uses a
// different and considerably more involved formula.
func ScoreCVSSVector(vector string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 2 || !strings.HasPrefix(strings.ToUpper(parts[0]), "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		m[strings.ToUpper(k)] = strings.ToUpper(v)
	}

	scopeChanged := m["S"] == "C"
	prTable := privRequiredUnchanged
	if scopeChanged {
		prTable = privRequiredChanged
	}

	av, ok1 := attackVector[m["AV"]]
	ac, ok2 := attackCplx[m["AC"]]
	pr, ok3 := prTable[m["PR"]]
	ui, ok4 := userInteract[m["UI"]]
	c, ok5 := impactWeight[m["C"]]
	i, ok6 := impactWeight[m["I"]]
	a, ok7 := impactWeight[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui

	base := impact + exploitability
	if scopeChanged {
		base *= 1.08
	}
	return roundUp(math.Min(base, 10)), true
}

// roundUp implements the specification's Roundup: the smallest number to one
// decimal place that is greater than or equal to the input. The integer
// arithmetic avoids the floating-point edge cases the specification calls out,
// where a naive ceil produces a score one tenth too high.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000.0
	}
	return (math.Floor(float64(i)/10000) + 1) / 10.0
}

// severityFromAdvisory picks the best severity signal an advisory offers.
//
// A computed CVSS v3 score is preferred because it is comparable across
// databases. Failing that, a database's own qualitative rating is used, which
// is the only signal available for advisories carrying just a CVSS v4 vector
// or none at all.
func severityFromAdvisory(vectors []string, vendorRating string) (string, float64) {
	best, found := 0.0, false
	for _, v := range vectors {
		if score, ok := ScoreCVSSVector(v); ok && score > best {
			best, found = score, true
		}
	}
	if found {
		return SeverityForScore(best), best
	}
	switch strings.ToUpper(strings.TrimSpace(vendorRating)) {
	case "CRITICAL":
		return SeverityCritical, 0
	case "HIGH", "IMPORTANT":
		return SeverityHigh, 0
	case "MEDIUM", "MODERATE":
		return SeverityMedium, 0
	case "LOW":
		return SeverityLow, 0
	}
	return SeverityUnknown, 0
}
