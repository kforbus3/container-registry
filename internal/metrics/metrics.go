// Package metrics exposes registry counters in the Prometheus text format.
//
// The exposition format is written directly rather than by depending on the
// client library: the registry publishes a few dozen series with no histograms
// or exemplars, and the format is a documented handful of lines.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Registry collects counters and gauges.
type Registry struct {
	mu       sync.RWMutex
	counters map[string]*series
	gauges   map[string]*series
	started  time.Time
}

type series struct {
	help   string
	values map[string]float64 // label set -> value
}

func New() *Registry {
	return &Registry{
		counters: map[string]*series{},
		gauges:   map[string]*series{},
		started:  time.Now(),
	}
}

// Labels is an ordered label set. Order is normalised on render so the same
// logical series always produces the same line.
type Labels map[string]string

func (l Labels) key() string {
	if len(l) == 0 {
		return ""
	}
	names := make([]string, 0, len(l))
	for k := range l {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(escapeLabelValue(l[n])))
	}
	return b.String()
}

// escapeLabelValue removes the characters that would break the exposition
// format. Label values here come from request paths and error codes, so they
// are not fully trusted.
func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}

// Inc adds one to a counter.
func (r *Registry) Inc(name, help string, labels Labels) { r.Add(name, help, labels, 1) }

// Add increases a counter.
func (r *Registry) Add(name, help string, labels Labels, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.counters[name]
	if !ok {
		s = &series{help: help, values: map[string]float64{}}
		r.counters[name] = s
	}
	s.values[labels.key()] += v
}

// SetGauge records a point-in-time value.
func (r *Registry) SetGauge(name, help string, labels Labels, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.gauges[name]
	if !ok {
		s = &series{help: help, values: map[string]float64{}}
		r.gauges[name] = s
	}
	s.values[labels.key()] = v
}

// Write renders the exposition format. Series are sorted so the output is
// stable, which makes it diffable and testable.
func (r *Registry) Write(w io.Writer) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.writeGroup(w, r.counters, "counter")
	r.writeGroup(w, r.gauges, "gauge")

	fmt.Fprintf(w, "# HELP registry_uptime_seconds Time since the registry started.\n")
	fmt.Fprintf(w, "# TYPE registry_uptime_seconds gauge\n")
	fmt.Fprintf(w, "registry_uptime_seconds %g\n", time.Since(r.started).Seconds())
}

func (r *Registry) writeGroup(w io.Writer, group map[string]*series, kind string) {
	names := make([]string, 0, len(group))
	for n := range group {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		s := group[name]
		if s.help != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", name, s.help)
		}
		fmt.Fprintf(w, "# TYPE %s %s\n", name, kind)

		keys := make([]string, 0, len(s.values))
		for k := range s.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				fmt.Fprintf(w, "%s %g\n", name, s.values[k])
			} else {
				fmt.Fprintf(w, "%s{%s} %g\n", name, k, s.values[k])
			}
		}
	}
}
