package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Moving blobs between backends.
//
// Changing where blobs live is the one configuration change that cannot simply
// be applied: the bytes already written do not move themselves, and a registry
// that switched backends without carrying them over would answer 404 for every
// image it already had. So the switch is a copy, a verification, and only then
// a swap.
//
// While the copy runs, writes go to both backends. Otherwise a push that landed
// after its part of the key space had been walked would exist only in the
// backend being left behind, and would vanish at the swap.

// MigrationState reports the progress of a backend migration.
type MigrationState struct {
	Running   bool      `json:"running"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Total     int64     `json:"total"`
	Copied    int64     `json:"copied"`
	Skipped   int64     `json:"skipped"`
	BytesDone int64     `json:"bytes_done"`
	BytesAll  int64     `json:"bytes_total"`
	Error     string    `json:"error,omitempty"`
	Done      bool      `json:"done"`
	StartedAt time.Time `json:"started_at,omitzero"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
}

// migration holds the live state of an in-flight or last-finished migration.
type migration struct {
	mu    sync.Mutex
	state MigrationState
}

func (m *migration) snapshot() MigrationState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *migration) update(fn func(*MigrationState)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(&m.state)
}

// SetBackend swaps the live backend without copying anything.
//
// Only safe when there is nothing to carry over -- a registry with blobs needs
// Migrate, or it would start answering 404 for everything it already had.
func (s *Store) SetBackend(b Backend) {
	s.backend.Store(&backendRef{b: b})
	s.router.SetFallback(b)
}

// Migrating reports whether a migration is currently running.
func (s *Store) Migrating() bool { return s.migration.snapshot().Running }

// MigrationState returns the current or most recent migration's progress.
func (s *Store) MigrationState() MigrationState { return s.migration.snapshot() }

// Migrate copies every blob into target and then makes it the live backend.
//
// It is safe to run against a serving registry: writes are mirrored to target
// for the duration, so anything pushed while the copy is in flight exists in
// both. Reads continue to come from the current backend until the swap, which
// is a single atomic store.
//
// Blobs are content-addressed, so a partial migration is not corruption: the
// objects already copied are byte-identical and a later attempt skips them.
func (s *Store) Migrate(ctx context.Context, target Backend, onDone func(error)) error {
	if target == nil {
		return fmt.Errorf("no target backend")
	}
	from := s.primary()
	if from.Name() == target.Name() {
		return fmt.Errorf("already storing blobs in %s", target.Name())
	}
	if !s.migrateStart(from.Name(), target.Name()) {
		return fmt.Errorf("a migration is already running")
	}

	// Mirror writes for the duration. Set before the walk begins so no write
	// can slip between the first listing and the first mirrored put.
	s.mirror.Store(&backendRef{b: target})

	go func() {
		err := s.copyAll(ctx, from, target)
		if err == nil {
			// The swap: from here reads come from target. Mirroring stops
			// after, never before, so there is no instant where a write could
			// reach neither backend.
			s.backend.Store(&backendRef{b: target})
			s.router.SetFallback(target)
			s.mirror.Store(&backendRef{})
		} else {
			s.mirror.Store(&backendRef{})
		}
		s.migrateFinish(err)
		if onDone != nil {
			onDone(err)
		}
	}()
	return nil
}

func (s *Store) migrateStart(from, to string) bool {
	s.migration.mu.Lock()
	defer s.migration.mu.Unlock()
	if s.migration.state.Running {
		return false
	}
	s.migration.state = MigrationState{
		Running: true, From: from, To: to, StartedAt: time.Now(),
	}
	return true
}

func (s *Store) migrateFinish(err error) {
	s.migration.update(func(st *MigrationState) {
		st.Running = false
		st.Done = err == nil
		st.EndedAt = time.Now()
		if err != nil {
			st.Error = err.Error()
		}
	})
}

// copyAll walks the source backend and copies what target does not already
// hold, verifying each object's digest as it goes.
func (s *Store) copyAll(ctx context.Context, from, target Backend) error {
	// A first pass counts the work, so progress is a fraction rather than a
	// number that only goes up.
	var total, totalBytes int64
	if err := from.Walk(ctx, "", func(info ObjectInfo) error {
		total++
		totalBytes += info.Size
		return nil
	}); err != nil {
		return fmt.Errorf("listing %s: %w", from.Name(), err)
	}
	s.migration.update(func(st *MigrationState) {
		st.Total = total
		st.BytesAll = totalBytes
	})

	return from.Walk(ctx, "", func(info ObjectInfo) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if existing, err := target.Stat(ctx, info.Key); err == nil && existing.Size == info.Size {
			s.migration.update(func(st *MigrationState) {
				st.Skipped++
				st.BytesDone += info.Size
			})
			return nil
		}
		if err := s.copyOne(ctx, from, target, info); err != nil {
			return fmt.Errorf("copying %s: %w", info.Key, err)
		}
		s.migration.update(func(st *MigrationState) {
			st.Copied++
			st.BytesDone += info.Size
		})
		return nil
	})
}

// copyOne streams a single object across and then verifies what actually
// landed in the target.
//
// The obvious implementation hashes the source stream on its way through, but
// that verifies the *read*, not the write: a backend that stores something
// other than what it was handed passes it. So the check is a read-back from the
// target, compared against the digest its own key encodes. That costs one extra
// read of every migrated object, which is the price of being able to say the
// copy is correct rather than that it completed.
func (s *Store) copyOne(ctx context.Context, from, target Backend, info ObjectInfo) error {
	rc, err := from.Get(ctx, info.Key)
	if err != nil {
		return err
	}
	err = target.Put(ctx, info.Key, rc, info.Size)
	rc.Close()
	if err != nil {
		return err
	}

	algo, want := keyDigest(info.Key)
	if algo == "" {
		return nil // not a content-addressed key; nothing to check it against
	}
	got, err := storedDigest(ctx, target, info.Key, algo)
	if err != nil {
		target.Delete(ctx, info.Key)
		return fmt.Errorf("reading back: %w", err)
	}
	if got != want {
		// Remove what was written: leaving the wrong bytes under a
		// content-addressed key is worse than failing the migration.
		target.Delete(ctx, info.Key)
		return fmt.Errorf("digest mismatch after copy: target holds %s:%s, key says %s:%s",
			algo, got, algo, want)
	}
	return nil
}

// storedDigest hashes an object as the backend actually stores it.
func storedDigest(ctx context.Context, b Backend, key, algo string) (string, error) {
	rc, err := b.Get(ctx, key)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	h, err := hasherFor(algo)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, rc); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// keyDigest recovers the algorithm and hex digest from a blob key of the form
// "<algo>/<first two chars>/<hex>". Anything else yields empty strings.
func keyDigest(key string) (algo, hexPart string) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 || len(parts[2]) < 2 || parts[1] != parts[2][:2] {
		return "", ""
	}
	return parts[0], parts[2]
}

// backendRef boxes a Backend so it can live in an atomic.Pointer. A nil b means
// "no backend", which is how mirroring is turned off.
type backendRef struct{ b Backend }

// primary is the backend reads come from and writes go to first.
func (s *Store) primary() Backend {
	return s.backend.Load().b
}

// mirrorTarget is the second backend writes are copied to during a migration,
// or nil when none is running.
func (s *Store) mirrorTarget() Backend {
	if r := s.mirror.Load(); r != nil {
		return r.b
	}
	return nil
}

// putTo writes to a specific backend, mirroring only when that backend is the
// one being migrated away from. A repository routed elsewhere is untouched by a
// migration of the default backend.
func (s *Store) putTo(ctx context.Context, b Backend, key string, r io.Reader, size int64) error {
	if b.Name() == s.primary().Name() {
		return s.putBoth(ctx, key, r, size)
	}
	return b.Put(ctx, key, r, size)
}

// deleteFrom removes an object from a specific backend.
func (s *Store) deleteFrom(ctx context.Context, b Backend, key string) error {
	if b.Name() == s.primary().Name() {
		return s.deleteBoth(ctx, key)
	}
	return b.Delete(ctx, key)
}

// putBoth writes to the primary backend and, during a migration, to the target.
//
// The mirror copy re-reads from the primary rather than teeing the original
// stream: a blob can be gigabytes, and buffering it to feed two writers would
// undo the streaming the rest of the upload path is careful to preserve.
func (s *Store) putBoth(ctx context.Context, key string, r io.Reader, size int64) error {
	primary := s.primary()
	if err := primary.Put(ctx, key, r, size); err != nil {
		return err
	}
	m := s.mirrorTarget()
	if m == nil {
		return nil
	}
	rc, err := primary.Get(ctx, key)
	if err != nil {
		return fmt.Errorf("mirroring %s: %w", key, err)
	}
	defer rc.Close()
	if err := m.Put(ctx, key, rc, size); err != nil {
		return fmt.Errorf("mirroring %s: %w", key, err)
	}
	return nil
}

// deleteBoth removes an object from the primary and, during a migration, from
// the target as well, so a blob collected mid-migration does not come back.
func (s *Store) deleteBoth(ctx context.Context, key string) error {
	if m := s.mirrorTarget(); m != nil {
		m.Delete(ctx, key)
	}
	return s.primary().Delete(ctx, key)
}
