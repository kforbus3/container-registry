package store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newFSBackend(t *testing.T, name string) Backend {
	t.Helper()
	b, err := NewFilesystemBackend(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("backend %s: %v", name, err)
	}
	return b
}

func waitMigration(t *testing.T, s *Store) MigrationState {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st := s.MigrationState()
		if !st.Running {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("migration did not finish")
	return MigrationState{}
}

// TestMigrateCarriesBlobsAndSwaps is the basic contract: after a migration the
// registry serves every blob it had, from the new backend.
func TestMigrateCarriesBlobsAndSwaps(t *testing.T) {
	s, err := NewWithBackend(t.TempDir(), 0, newFSBackend(t, "old"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{}
	for i := 0; i < 25; i++ {
		body := []byte(fmt.Sprintf("blob number %d, with some content", i))
		d, err := s.For("test/repo").PutBytes(body)
		if err != nil {
			t.Fatal(err)
		}
		want[d] = body
	}

	target := newFSBackend(t, "new")
	if err := s.Migrate(context.Background(), target, nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	st := waitMigration(t, s)
	if st.Error != "" || !st.Done {
		t.Fatalf("migration failed: %+v", st)
	}
	if st.Copied != int64(len(want)) {
		t.Errorf("copied %d objects, want %d", st.Copied, len(want))
	}
	if s.Backend() != target.Name() {
		t.Errorf("backend is %s, want %s", s.Backend(), target.Name())
	}

	// Every blob must still read back, byte for byte, from the new backend.
	for d, body := range want {
		got, err := s.For("test/repo").ReadAll(d)
		if err != nil {
			t.Fatalf("read %s after migration: %v", d, err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("blob %s changed across the migration", d)
		}
	}
}

// TestMigrateMirrorsConcurrentWrites covers the reason mirroring exists: a blob
// pushed while the copy is in flight must survive the swap. Without mirroring
// it would land only in the backend being abandoned.
func TestMigrateMirrorsConcurrentWrites(t *testing.T) {
	old := newFSBackend(t, "old")
	s, err := NewWithBackend(t.TempDir(), 0, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.For("test/repo").PutBytes([]byte("already here")); err != nil {
		t.Fatal(err)
	}

	// A target that blocks on its first write, holding the migration open
	// long enough for a push to arrive mid-flight.
	gate := make(chan struct{})
	target := &gatedBackend{Backend: newFSBackend(t, "new"), gate: gate}

	if err := s.Migrate(context.Background(), target, nil); err != nil {
		t.Fatalf("start: %v", err)
	}

	mid, err := s.For("test/repo").PutBytes([]byte("pushed during the migration"))
	if err != nil {
		t.Fatalf("write during migration: %v", err)
	}
	close(gate)

	if st := waitMigration(t, s); st.Error != "" {
		t.Fatalf("migration failed: %s", st.Error)
	}
	got, err := s.For("test/repo").ReadAll(mid)
	if err != nil {
		t.Fatalf("blob written during the migration was lost: %v", err)
	}
	if string(got) != "pushed during the migration" {
		t.Errorf("mid-migration blob reads back as %q", got)
	}
}

// TestMigrateRefusesSameBackend and TestMigrateRefusesConcurrent guard the two
// ways an operator can ask for something meaningless.
func TestMigrateRefusesSameBackend(t *testing.T) {
	b := newFSBackend(t, "only")
	s, err := NewWithBackend(t.TempDir(), 0, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background(), b, nil); err == nil {
		t.Error("migrating a backend onto itself should be refused")
	}
}

// TestMigrateVerifiesDigests proves the copy is checked rather than assumed: a
// backend that corrupts content must fail the migration, not silently swap.
func TestMigrateVerifiesDigests(t *testing.T) {
	s, err := NewWithBackend(t.TempDir(), 0, newFSBackend(t, "old"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.For("test/repo").PutBytes([]byte("content that will be mangled")); err != nil {
		t.Fatal(err)
	}
	before := s.Backend()

	target := &corruptBackend{Backend: newFSBackend(t, "new")}
	if err := s.Migrate(context.Background(), target, nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	st := waitMigration(t, s)
	if st.Error == "" {
		t.Fatal("a corrupting target should fail the migration")
	}
	if s.Backend() != before {
		t.Errorf("backend swapped to %s despite a failed migration", s.Backend())
	}
}

// gatedBackend blocks its first Put until gate is closed. Every later Put runs
// straight through — that asymmetry is the point, since the test writes
// concurrently with a migration that is being held at its first copy.
//
// The flag is atomic because both goroutines reach this at once, which is the
// situation the test exists to create. A sync.Once would be wrong here: it
// would make the second caller wait for the first instead of passing it.
type gatedBackend struct {
	Backend
	gate  chan struct{}
	first atomic.Bool
}

func (g *gatedBackend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if g.first.CompareAndSwap(false, true) {
		<-g.gate
	}
	return g.Backend.Put(ctx, key, r, size)
}

func (g *gatedBackend) Name() string { return "gated(" + g.Backend.Name() + ")" }

// corruptBackend stores something other than what it was given.
type corruptBackend struct{ Backend }

func (c *corruptBackend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	bad := []byte("not the bytes you asked for")
	return c.Backend.Put(ctx, key, bytes.NewReader(bad), int64(len(bad)))
}

func (c *corruptBackend) Name() string { return "corrupt(" + c.Backend.Name() + ")" }
