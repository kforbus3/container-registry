package vuln

import (
	"math"
	"testing"
)

// Vectors and expected base scores taken from the worked examples in the
// CVSS v3.1 specification and from published advisories.
func TestScoreCVSSVector(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		// CVSS v3.1 specification, section 8 examples.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0},
		// The lodash command-injection advisory, scored HIGH by GitHub.
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2},
		// v3.0 vectors use the same formula.
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, c := range cases {
		got, ok := ScoreCVSSVector(c.vector)
		if !ok {
			t.Errorf("%s: rejected", c.vector)
			continue
		}
		if math.Abs(got-c.want) > 0.001 {
			t.Errorf("%s: score = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestScoreCVSSVectorRejectsUnsupported(t *testing.T) {
	// v2 and v4 use different formulas; anything unparseable must not be
	// silently scored as zero-and-valid, which would read as "not vulnerable".
	for _, v := range []string{
		"",
		"AV:N/AC:L/Au:N/C:P/I:P/A:P",          // v2, no prefix
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", // v2
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", // v4
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // bad metric value
		"not a vector at all",
	} {
		if _, ok := ScoreCVSSVector(v); ok {
			t.Errorf("%q was accepted but should not have been", v)
		}
	}
}

func TestSeverityForScore(t *testing.T) {
	cases := map[float64]string{
		0.0: SeverityUnknown,
		0.1: SeverityLow,
		3.9: SeverityLow,
		4.0: SeverityMedium,
		6.9: SeverityMedium,
		7.0: SeverityHigh,
		8.9: SeverityHigh,
		9.0: SeverityCritical,
		10:  SeverityCritical,
	}
	for score, want := range cases {
		if got := SeverityForScore(score); got != want {
			t.Errorf("SeverityForScore(%.1f) = %s, want %s", score, got, want)
		}
	}
}

// A computed vector beats a vendor's own label, because the same CVE is
// routinely rated differently by different databases.
func TestSeverityFromAdvisoryPrefersComputedScore(t *testing.T) {
	sev, score := severityFromAdvisory(
		[]string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "LOW")
	if sev != SeverityCritical || math.Abs(score-9.8) > 0.001 {
		t.Fatalf("got %s/%.1f, want CRITICAL/9.8 from the vector rather than the vendor label", sev, score)
	}

	// With no usable vector, fall back to the vendor rating.
	sev, _ = severityFromAdvisory([]string{"CVSS:4.0/AV:N/AC:L"}, "Important")
	if sev != SeverityHigh {
		t.Fatalf("vendor rating fallback = %s, want HIGH", sev)
	}
	// And with neither, say so rather than implying safety.
	if sev, _ := severityFromAdvisory(nil, ""); sev != SeverityUnknown {
		t.Fatalf("empty advisory = %s, want UNKNOWN", sev)
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	if !(SeverityRank(SeverityCritical) > SeverityRank(SeverityHigh) &&
		SeverityRank(SeverityHigh) > SeverityRank(SeverityMedium) &&
		SeverityRank(SeverityMedium) > SeverityRank(SeverityLow) &&
		SeverityRank(SeverityLow) > SeverityRank(SeverityUnknown)) {
		t.Fatal("severity ordering is wrong")
	}
}
