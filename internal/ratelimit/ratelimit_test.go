package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestDisabledLimitAllowsEverything(t *testing.T) {
	l := New(Limit{PerMinute: 0})
	for i := 0; i < 1000; i++ {
		if ok, _ := l.Allow("someone"); !ok {
			t.Fatalf("request %d was blocked by a disabled limiter", i)
		}
	}
}

func TestBurstThenThrottle(t *testing.T) {
	l := New(Limit{PerMinute: 60, Burst: 5})
	start := time.Now()

	// The burst allowance is spendable immediately.
	for i := 0; i < 5; i++ {
		if ok, _ := l.allowAt("a", start); !ok {
			t.Fatalf("burst request %d was blocked", i)
		}
	}
	// The sixth has nothing left.
	ok, retry := l.allowAt("a", start)
	if ok {
		t.Fatal("request beyond the burst was allowed")
	}
	if retry <= 0 {
		t.Fatal("a blocked request must say when to retry")
	}
}

func TestRefillOverTime(t *testing.T) {
	l := New(Limit{PerMinute: 60, Burst: 1}) // one per second
	start := time.Now()

	if ok, _ := l.allowAt("a", start); !ok {
		t.Fatal("first request blocked")
	}
	if ok, _ := l.allowAt("a", start); ok {
		t.Fatal("second immediate request should have been blocked")
	}
	// A second later exactly one token is back.
	if ok, _ := l.allowAt("a", start.Add(time.Second)); !ok {
		t.Fatal("request after the refill interval was blocked")
	}
	if ok, _ := l.allowAt("a", start.Add(time.Second)); ok {
		t.Fatal("only one token should have been restored")
	}
}

// Idle time must not bank unlimited credit, or a caller could sleep an hour and
// then fire an hour's worth of requests at once.
func TestRefillIsCappedAtBurst(t *testing.T) {
	l := New(Limit{PerMinute: 60, Burst: 3})
	start := time.Now()
	// Drain it.
	for i := 0; i < 3; i++ {
		l.allowAt("a", start)
	}
	// Come back an hour later: only the burst allowance is available.
	later := start.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _ := l.allowAt("a", later); !ok {
			t.Fatalf("request %d after a long idle was blocked", i)
		}
	}
	if ok, _ := l.allowAt("a", later); ok {
		t.Fatal("an hour of idling banked more than the burst allowance")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(Limit{PerMinute: 60, Burst: 1})
	start := time.Now()

	if ok, _ := l.allowAt("a", start); !ok {
		t.Fatal("first caller blocked")
	}
	if ok, _ := l.allowAt("a", start); ok {
		t.Fatal("first caller should now be throttled")
	}
	// A different caller has its own allowance.
	if ok, _ := l.allowAt("b", start); !ok {
		t.Fatal("one caller's usage throttled another")
	}
}

// The bucket map must not grow forever as distinct callers come and go.
func TestIdleBucketsAreCollected(t *testing.T) {
	l := New(Limit{PerMinute: 60, Burst: 1})
	start := time.Now()
	for i := 0; i < 50; i++ {
		l.allowAt(string(rune('a'+i%26))+string(rune('a'+i/26)), start)
	}
	if l.Len() < 40 {
		t.Fatalf("tracking %d buckets, expected around 50", l.Len())
	}
	// Long after everything has refilled, a new request triggers a sweep.
	l.allowAt("trigger", start.Add(time.Hour))
	if l.Len() > 5 {
		t.Fatalf("still tracking %d buckets after a sweep", l.Len())
	}
}

func TestRetryAfterIsNeverZero(t *testing.T) {
	// A very high rate could round the wait down to nothing, which would tell
	// the client to retry immediately and spin.
	l := New(Limit{PerMinute: 600000, Burst: 1})
	start := time.Now()
	l.allowAt("a", start)
	ok, retry := l.allowAt("a", start)
	if ok {
		t.Fatal("expected the second request to be blocked")
	}
	if retry < time.Second {
		t.Fatalf("Retry-After = %v, want at least a second", retry)
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l := New(Limit{PerMinute: 6000, Burst: 100})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Allow("shared")
				l.Allow(string(rune('a' + n)))
			}
		}(i)
	}
	wg.Wait()
}
