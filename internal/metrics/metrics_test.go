package metrics

import (
	"strings"
	"testing"
)

func render(r *Registry) string {
	var b strings.Builder
	r.Write(&b)
	return b.String()
}

func TestCounterAndGaugeExposition(t *testing.T) {
	r := New()
	r.Inc("registry_requests_total", "Requests served.", Labels{"method": "GET", "code": "200"})
	r.Inc("registry_requests_total", "Requests served.", Labels{"method": "GET", "code": "200"})
	r.Inc("registry_requests_total", "Requests served.", Labels{"method": "PUT", "code": "201"})
	r.SetGauge("registry_repositories", "Repositories.", nil, 7)

	out := render(r)
	for _, want := range []string{
		"# TYPE registry_requests_total counter",
		`registry_requests_total{code="200",method="GET"} 2`,
		`registry_requests_total{code="201",method="PUT"} 1`,
		"# TYPE registry_repositories gauge",
		"registry_repositories 7",
		"registry_uptime_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Labels are sorted so one logical series always renders identically,
// regardless of map iteration order.
func TestOutputIsStable(t *testing.T) {
	build := func() string {
		r := New()
		for i := 0; i < 5; i++ {
			r.Inc("x_total", "help", Labels{"z": "1", "a": "2", "m": "3"})
		}
		// Uptime legitimately differs between renders, so it is excluded from
		// the comparison; everything else must be byte-identical.
		var kept []string
		for _, line := range strings.Split(render(r), "\n") {
			if !strings.Contains(line, "uptime_seconds") {
				kept = append(kept, line)
			}
		}
		return strings.Join(kept, "\n")
	}
	first := build()
	for i := 0; i < 5; i++ {
		if build() != first {
			t.Fatal("rendering is not deterministic")
		}
	}
	if !strings.Contains(first, `x_total{a="2",m="3",z="1"} 5`) {
		t.Fatalf("labels are not sorted:\n%s", first)
	}
}

// Label values come from paths and error codes, so they must not be able to
// break the format.
func TestLabelValuesAreEscaped(t *testing.T) {
	r := New()
	r.Inc("x_total", "help", Labels{"path": "a\nb\\c"})
	out := render(r)
	if strings.Count(out, "\n") != strings.Count(strings.TrimRight(out, "\n"), "\n")+1 {
		// A newline injected into a label would add a stray line.
		t.Fatalf("output has an unexpected line structure:\n%q", out)
	}
	if strings.Contains(out, "a\nb") {
		t.Fatalf("a newline survived into the output:\n%q", out)
	}
}
