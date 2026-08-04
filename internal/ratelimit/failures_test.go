package ratelimit

import (
	"testing"
	"time"
)

func TestFailuresToleratesThenThrottles(t *testing.T) {
	f := NewFailures(3, time.Minute, time.Minute)
	start := time.Now()

	for i := 0; i < 2; i++ {
		f.failAt(start, "ip:198.51.100.7")
		if blocked, _ := f.blockedAt(start, "ip:198.51.100.7"); blocked {
			t.Fatalf("blocked after %d failures, threshold is 3", i+1)
		}
	}
	f.failAt(start, "ip:198.51.100.7")
	blocked, wait := f.blockedAt(start, "ip:198.51.100.7")
	if !blocked {
		t.Fatal("not blocked after reaching the threshold")
	}
	if wait <= 0 {
		t.Fatalf("wait = %v, want a positive duration", wait)
	}
}

func TestFailuresBackoffGrowsAndIsCapped(t *testing.T) {
	f := NewFailures(1, time.Hour, 8*time.Second)
	start := time.Now()

	var last time.Duration
	for i := 0; i < 4; i++ {
		f.failAt(start, "user:admin")
		_, wait := f.blockedAt(start, "user:admin")
		if i > 0 && wait < last {
			t.Fatalf("wait shrank from %v to %v", last, wait)
		}
		last = wait
	}
	if last != 8*time.Second {
		t.Fatalf("wait = %v, want it capped at 8s", last)
	}
}

func TestFailuresExpireAndClear(t *testing.T) {
	f := NewFailures(2, time.Minute, time.Minute)
	start := time.Now()

	f.failAt(start, "ip:203.0.113.9")
	f.failAt(start, "ip:203.0.113.9")
	if blocked, _ := f.blockedAt(start, "ip:203.0.113.9"); !blocked {
		t.Fatal("not blocked at the threshold")
	}

	// The wait runs out on its own.
	if blocked, _ := f.blockedAt(start.Add(2*time.Minute), "ip:203.0.113.9"); blocked {
		t.Fatal("still blocked long after the wait expired")
	}

	// And a success clears the record outright.
	f.failAt(start, "ip:203.0.113.9")
	f.Succeed("ip:203.0.113.9")
	if blocked, _ := f.blockedAt(start, "ip:203.0.113.9"); blocked {
		t.Fatal("still blocked after a successful authentication")
	}
}

// Any key being blocked blocks the attempt: one host working through a list of
// accounts and many hosts working on one account are both bounded.
func TestFailuresBlockOnAnyKey(t *testing.T) {
	f := NewFailures(1, time.Minute, time.Minute)
	start := time.Now()
	f.failAt(start, "user:admin")

	if blocked, _ := f.blockedAt(start, "ip:192.0.2.1", "user:admin"); !blocked {
		t.Fatal("a fresh address must not escape a locked account")
	}
	if blocked, _ := f.blockedAt(start, "ip:192.0.2.1", "user:someone-else"); blocked {
		t.Fatal("an unrelated account was caught up in it")
	}
}

// A threshold of zero turns the feature off rather than blocking everything.
func TestFailuresDisabled(t *testing.T) {
	f := NewFailures(0, time.Minute, time.Minute)
	now := time.Now()
	for i := 0; i < 50; i++ {
		f.failAt(now, "ip:192.0.2.1")
	}
	if blocked, _ := f.blockedAt(now, "ip:192.0.2.1"); blocked {
		t.Fatal("blocked with the throttle disabled")
	}
}
