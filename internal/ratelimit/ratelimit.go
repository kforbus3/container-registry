// Package ratelimit bounds how fast one caller can drive the registry.
//
// Without it a single valid token can saturate upload capacity and fill the
// disk, which is a denial of service that authentication does nothing to stop.
package ratelimit

import (
	"sync"
	"time"
)

// Limit is a rate expressed as a sustained rate plus a burst allowance.
type Limit struct {
	// PerMinute is the sustained rate. Zero disables the limit entirely.
	PerMinute int
	// Burst is how many requests may arrive at once before the sustained rate
	// starts to bite. Zero defaults to one second's worth, minimum one.
	Burst int
}

// Enabled reports whether the limit constrains anything.
func (l Limit) Enabled() bool { return l.PerMinute > 0 }

func (l Limit) burst() float64 {
	if l.Burst > 0 {
		return float64(l.Burst)
	}
	if b := float64(l.PerMinute) / 60; b > 1 {
		return b
	}
	return 1
}

// bucket is a token bucket refilled continuously rather than on a timer, so an
// idle caller regains its allowance without any background work.
type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter applies limits to named callers.
//
// Buckets are held in memory, which means limits are per process: two registry
// instances behind a load balancer each enforce their own. That is a deliberate
// trade — a shared counter would need a shared store and turn every request
// into a network round trip.
type Limiter struct {
	limit Limit

	mu      sync.Mutex
	buckets map[string]*bucket
	// lastSweep bounds how often idle buckets are collected, so a burst of
	// distinct keys cannot make every request pay for a full scan.
	lastSweep time.Time
}

func New(limit Limit) *Limiter {
	return &Limiter{
		limit:     limit,
		buckets:   map[string]*bucket{},
		lastSweep: time.Now(),
	}
}

// Allow reports whether the key may proceed, and if not, how long until it can.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	return l.allowAt(key, time.Now())
}

func (l *Limiter) allowAt(key string, now time.Time) (bool, time.Duration) {
	if !l.limit.Enabled() {
		return true, 0
	}
	perSecond := float64(l.limit.PerMinute) / 60
	capacity := l.limit.burst()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		l.buckets[key] = b
	} else {
		// Refill for the time elapsed, capped at the burst allowance so a long
		// idle period does not bank unlimited credit.
		b.tokens += now.Sub(b.last).Seconds() * perSecond
		if b.tokens > capacity {
			b.tokens = capacity
		}
		b.last = now
	}

	l.sweepLocked(now)

	if b.tokens < 1 {
		// Time until one whole token is available again.
		deficit := 1 - b.tokens
		wait := time.Duration(deficit / perSecond * float64(time.Second))
		if wait < time.Second {
			wait = time.Second // Retry-After is whole seconds; never advertise 0
		}
		return false, wait
	}
	b.tokens--
	return true, 0
}

// sweepLocked drops buckets that have been full and untouched long enough that
// forgetting them changes nothing. Without it the map grows once per distinct
// caller and never shrinks.
func (l *Limiter) sweepLocked(now time.Time) {
	const sweepInterval = 5 * time.Minute
	if now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now

	perSecond := float64(l.limit.PerMinute) / 60
	capacity := l.limit.burst()
	// A bucket is forgettable once it would have refilled completely.
	idleFor := time.Duration(capacity/perSecond*float64(time.Second)) + sweepInterval
	for key, b := range l.buckets {
		if now.Sub(b.last) > idleFor {
			delete(l.buckets, key)
		}
	}
}

// Len reports how many buckets are being tracked. Used by tests and metrics.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
