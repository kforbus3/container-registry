package ratelimit

import (
	"sync"
	"time"
)

// Failures throttles repeated authentication failures.
//
// The request limiter above cannot do this job: it runs once a caller is known,
// which is exactly the point a rejected credential never reaches. Without a
// separate bound, password guessing is free — and because every attempt costs a
// bcrypt hash, so is burning the registry's CPU.
//
// Attempts are counted per key. A caller under the threshold is not delayed at
// all, so a mistyped password costs nothing; past it the wait doubles with each
// further failure, up to Max. One success clears the record.
type Failures struct {
	// Threshold is how many failures are tolerated before waiting begins.
	// Zero disables throttling entirely.
	Threshold int
	// Base is the first wait imposed once the threshold is passed.
	Base time.Duration
	// Max caps the wait, so a locked-out key recovers in bounded time rather
	// than being shut out for ever by a script that keeps trying.
	Max time.Duration
	// Window is how long a quiet key keeps its failure count. It bounds memory
	// as much as behaviour: records older than this are dropped.
	Window time.Duration

	mu        sync.Mutex
	entries   map[string]*failureEntry
	lastSweep time.Time
}

type failureEntry struct {
	count int
	// until is when the key may try again; zero means now.
	until time.Time
	seen  time.Time
}

// NewFailures builds a tracker. Sensible defaults are filled in for anything
// left at zero except Threshold, which is what turns the feature on.
func NewFailures(threshold int, window, max time.Duration) *Failures {
	f := &Failures{
		Threshold: threshold,
		Base:      time.Second,
		Max:       max,
		Window:    window,
		entries:   map[string]*failureEntry{},
		lastSweep: time.Now(),
	}
	if f.Max <= 0 {
		f.Max = 15 * time.Minute
	}
	if f.Window <= 0 {
		f.Window = 15 * time.Minute
	}
	return f
}

// Blocked reports whether a key is currently waiting out a failure, and for how
// much longer.
func (f *Failures) Blocked(keys ...string) (bool, time.Duration) {
	return f.blockedAt(time.Now(), keys...)
}

func (f *Failures) blockedAt(now time.Time, keys ...string) (bool, time.Duration) {
	if f == nil || f.Threshold <= 0 {
		return false, 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	var longest time.Duration
	for _, key := range keys {
		e, ok := f.entries[key]
		if !ok {
			continue
		}
		if wait := e.until.Sub(now); wait > longest {
			longest = wait
		}
	}
	return longest > 0, longest
}

// Fail records a failed attempt against every key it is given — typically the
// caller's address and the account being tried, so that neither one host
// working through a list of accounts nor many hosts working on one account goes
// unbounded.
func (f *Failures) Fail(keys ...string) {
	f.failAt(time.Now(), keys...)
}

func (f *Failures) failAt(now time.Time, keys ...string) {
	if f == nil || f.Threshold <= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now)

	for _, key := range keys {
		e, ok := f.entries[key]
		if !ok || now.Sub(e.seen) > f.Window {
			e = &failureEntry{}
			f.entries[key] = e
		}
		e.count++
		e.seen = now
		// The threshold counts attempts that are tolerated, so the wait starts
		// on the attempt that reaches it rather than the one after.
		if e.count >= f.Threshold {
			e.until = now.Add(f.backoff(e.count))
		}
	}
}

// backoff doubles per failure past the threshold, capped at Max. It is computed
// by shifting rather than looping so a large count costs nothing.
func (f *Failures) backoff(count int) time.Duration {
	base := f.Base
	if base <= 0 {
		base = time.Second
	}
	steps := count - f.Threshold
	if steps < 0 {
		steps = 0
	}
	if steps > 20 { // 2^20 seconds is already far past any sane Max
		return f.Max
	}
	wait := base << steps
	if wait > f.Max || wait <= 0 {
		return f.Max
	}
	return wait
}

// Succeed clears the record for every key, so a legitimate login is not
// punished for earlier typos.
func (f *Failures) Succeed(keys ...string) {
	if f == nil || f.Threshold <= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, key := range keys {
		delete(f.entries, key)
	}
}

// sweepLocked drops records that have aged out. Like the limiter's sweep it is
// rate-limited itself, so a flood of distinct keys does not make every attempt
// pay for a full scan.
func (f *Failures) sweepLocked(now time.Time) {
	if now.Sub(f.lastSweep) < time.Minute {
		return
	}
	f.lastSweep = now
	for key, e := range f.entries {
		if now.Sub(e.seen) > f.Window && now.After(e.until) {
			delete(f.entries, key)
		}
	}
}
