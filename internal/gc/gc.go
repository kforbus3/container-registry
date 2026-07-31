// Package gc reclaims disk space from blobs no live manifest references.
package gc

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/store"
)

// Result summarises a collection run.
type Result struct {
	StartedAt      time.Time `json:"started_at"`
	Duration       string    `json:"duration"`
	DryRun         bool      `json:"dry_run"`
	LinksPruned    int       `json:"links_pruned"`
	BlobsScanned   int       `json:"blobs_scanned"`
	BlobsDeleted   int       `json:"blobs_deleted"`
	BytesReclaimed int64     `json:"bytes_reclaimed"`
	BlobsSkipped   int       `json:"blobs_skipped_grace"`
	UploadsPurged  int       `json:"uploads_purged"`
	Errors         []string  `json:"errors,omitempty"`
}

// Collector serialises garbage collection runs; two concurrent sweeps would
// race each other's reachability snapshots.
type Collector struct {
	DB    *db.DB
	Store *store.Store
	Log   *slog.Logger

	// Grace protects blobs written recently but not yet referenced by a
	// manifest, which is the normal state mid-push.
	Grace time.Duration
	// UploadTTL bounds how long an abandoned upload session is kept.
	UploadTTL time.Duration

	mu      sync.Mutex
	running bool
	last    *Result
}

func New(database *db.DB, st *store.Store, log *slog.Logger) *Collector {
	return &Collector{DB: database, Store: st, Log: log, Grace: time.Hour, UploadTTL: 24 * time.Hour}
}

// Last returns the most recent result, or nil if none has run.
func (c *Collector) Last() *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func (c *Collector) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Run performs a mark-and-sweep collection. With dryRun set, nothing is
// deleted and the result reports what would have been.
func (c *Collector) Run(ctx context.Context, dryRun bool) (*Result, error) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil, fmt.Errorf("garbage collection is already running")
	}
	c.running = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	started := time.Now()
	res := &Result{StartedAt: started.UTC(), DryRun: dryRun}

	if n, err := c.Store.PurgeStaleUploads(c.UploadTTL); err != nil {
		res.Errors = append(res.Errors, "purge uploads: "+err.Error())
	} else {
		res.UploadsPurged = n
	}

	// Mark phase 1: drop repository blob links no manifest in that repository
	// depends on. This must happen before the reachability snapshot. A dry run
	// finds the same links but leaves them in place, so its report matches what
	// a real run would do.
	var pruned []db.BlobLink
	var err error
	if dryRun {
		pruned, err = c.DB.FindUnreferencedBlobLinks(ctx)
	} else {
		pruned, err = c.DB.PruneUnreferencedBlobLinks(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("prune blob links: %w", err)
	}
	res.LinksPruned = len(pruned)

	// Mark phase 2: everything still reachable from a live manifest.
	reachable, err := c.DB.ReachableDigests(ctx)
	if err != nil {
		return nil, fmt.Errorf("compute reachable set: %w", err)
	}

	cutoff := time.Now().Add(-c.Grace)

	// Sweep: delete blobs on disk that nothing points at. Collect first so the
	// walk is not mutating the tree it is reading.
	type victim struct {
		digest string
		size   int64
	}
	var victims []victim
	err = c.Store.WalkBlobs(func(digest string, size int64) error {
		res.BlobsScanned++
		if _, ok := reachable[digest]; ok {
			return nil
		}
		if _, mtime, err := c.Store.Stat(digest); err == nil && mtime.After(cutoff) {
			// Recently written: probably a push in flight.
			res.BlobsSkipped++
			return nil
		}
		victims = append(victims, victim{digest, size})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk blobs: %w", err)
	}

	for _, v := range victims {
		if !dryRun {
			// Re-check under the current database state: a push may have landed
			// between the snapshot and now. A dry run skips this because the
			// links it would have pruned are deliberately still in place.
			if _, linked, err := c.DB.AnyBlobLink(ctx, v.digest); err == nil && linked {
				res.BlobsSkipped++
				continue
			}
		}
		res.BlobsDeleted++
		res.BytesReclaimed += v.size
		if dryRun {
			continue
		}
		if err := c.Store.Delete(v.digest); err != nil {
			res.Errors = append(res.Errors, v.digest+": "+err.Error())
			res.BlobsDeleted--
			res.BytesReclaimed -= v.size
		}
	}

	res.Duration = time.Since(started).Round(time.Millisecond).String()
	c.mu.Lock()
	c.last = res
	c.mu.Unlock()

	c.Log.Info("garbage collection complete",
		"dry_run", dryRun, "scanned", res.BlobsScanned, "deleted", res.BlobsDeleted,
		"reclaimed_bytes", res.BytesReclaimed, "duration", res.Duration)
	return res, nil
}
