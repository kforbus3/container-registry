package gc

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
)

// Scheduler runs retention and garbage collection on an interval.
//
// Without it, storage only ever grows: collection previously ran when somebody
// remembered to ask for it, which is not a maintenance strategy.
type Scheduler struct {
	DB        *db.DB
	Retention *Retention
	Collector *Collector
	Log       *slog.Logger

	// Interval is how often a sweep runs. Zero disables scheduling entirely.
	Interval time.Duration
	// InitialDelay staggers the first run so a restart loop cannot turn into a
	// collection loop.
	InitialDelay time.Duration

	// AdvisoryTTL bounds how long an unreferenced cached advisory is kept.
	// Zero leaves the advisory cache alone.
	AdvisoryTTL time.Duration
}

// Run blocks until the context is cancelled, sweeping on the interval.
func (s *Scheduler) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Log.Info("scheduled maintenance is disabled")
		return
	}
	delay := s.InitialDelay
	if delay <= 0 {
		delay = time.Minute
	}
	s.Log.Info("scheduled maintenance enabled",
		"interval", s.Interval.String(), "first_run_in", delay.String())

	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.Sweep(ctx, "schedule")
			timer.Reset(s.Interval)
		}
	}
}

// Sweep applies retention and then collects. The order matters: retention
// decides what is no longer wanted, and collection is what actually frees the
// space, so running them the other way round would always lag by one cycle.
func (s *Scheduler) Sweep(ctx context.Context, trigger string) {
	started := time.Now()
	ret, err := s.Retention.ApplyAll(ctx, false)
	if err != nil {
		s.Log.Error("retention sweep failed", "err", err)
	} else if ret.TagsDeleted > 0 || len(ret.Errors) > 0 {
		s.Log.Info("retention applied",
			"repositories", ret.Repositories, "tags_deleted", ret.TagsDeleted,
			"protected", ret.Protected, "errors", len(ret.Errors))
		s.DB.RecordMaintenanceRun(ctx, &db.MaintenanceRun{
			Kind: "retention", Trigger: trigger,
			TagsDeleted: ret.TagsDeleted,
			Detail:      fmt.Sprintf("%d repositories, %d protected", ret.Repositories, ret.Protected),
			StartedAt:   started,
			DurationMS:  time.Since(started).Milliseconds(),
		})
	}

	// The advisory cache is swept here too: it is storage that grows on its
	// own, which is exactly what this sweep exists to bound.
	if n, err := s.DB.PruneAdvisories(ctx, s.AdvisoryTTL); err != nil {
		s.Log.Error("advisory cache prune failed", "err", err)
	} else if n > 0 {
		s.Log.Info("pruned unreferenced advisories", "count", n)
	}

	gcStart := time.Now()
	res, err := s.Collector.Run(ctx, false)
	if err != nil {
		// A collection already in progress is normal, not an error worth
		// shouting about.
		s.Log.Debug("scheduled collection skipped", "reason", err)
		return
	}
	if res.BlobsDeleted > 0 || res.LinksPruned > 0 {
		s.DB.RecordMaintenanceRun(ctx, &db.MaintenanceRun{
			Kind: "gc", Trigger: trigger,
			BlobsDeleted: res.BlobsDeleted, BytesFreed: res.BytesReclaimed,
			Detail:     fmt.Sprintf("%d links pruned, %d skipped by grace", res.LinksPruned, res.BlobsSkipped),
			StartedAt:  gcStart,
			DurationMS: time.Since(gcStart).Milliseconds(),
		})
	}
}
