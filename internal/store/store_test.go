package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T, maxBytes int64) *Store {
	t.Helper()
	s, err := New(t.TempDir(), maxBytes)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestParseDigest(t *testing.T) {
	good := digestOf([]byte("hello"))
	if _, _, err := ParseDigest(good); err != nil {
		t.Fatalf("valid digest rejected: %v", err)
	}
	bad := []string{
		"", "sha256", "sha256:", "nope:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("z", 64), // not hex
		strings.Repeat("a", 64),
	}
	for _, d := range bad {
		if _, _, err := ParseDigest(d); err == nil {
			t.Errorf("ParseDigest(%q) should have failed", d)
		}
	}
}

func TestUploadRoundTrip(t *testing.T) {
	s := newTestStore(t, 0)
	content := []byte("layer content that spans a few chunks")

	up, err := s.NewUpload()
	if err != nil {
		t.Fatalf("NewUpload: %v", err)
	}
	if up.Offset != 0 {
		t.Fatalf("fresh upload offset = %d, want 0", up.Offset)
	}

	// Push in three chunks, asserting the offset each time, which is what a
	// chunked client does with Content-Range.
	var sent int64
	for _, chunk := range [][]byte{content[:10], content[10:22], content[22:]} {
		got, err := s.Append(up.ID, bytes.NewReader(chunk), sent)
		if err != nil {
			t.Fatalf("Append at %d: %v", sent, err)
		}
		sent += int64(len(chunk))
		if got.Offset != sent {
			t.Fatalf("offset after append = %d, want %d", got.Offset, sent)
		}
	}

	size, err := s.For("test/repo").Commit(up.ID, digestOf(content))
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if size != int64(len(content)) {
		t.Fatalf("committed size = %d, want %d", size, len(content))
	}
	got, err := s.For("test/repo").ReadAll(digestOf(content))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("stored content does not round-trip")
	}
}

func TestUploadRejectsWrongOffset(t *testing.T) {
	s := newTestStore(t, 0)
	up, _ := s.NewUpload()
	if _, err := s.Append(up.ID, strings.NewReader("abc"), 0); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// Client claims to resume at 99 when the server holds 3 bytes.
	if _, err := s.Append(up.ID, strings.NewReader("def"), 99); err != ErrBadOffset {
		t.Fatalf("err = %v, want ErrBadOffset", err)
	}
}

func TestCommitRejectsDigestMismatch(t *testing.T) {
	s := newTestStore(t, 0)
	up, _ := s.NewUpload()
	s.Append(up.ID, strings.NewReader("actual content"), 0)

	wrong := digestOf([]byte("different content"))
	if _, err := s.For("test/repo").Commit(up.ID, wrong); err == nil {
		t.Fatal("Commit accepted a mismatched digest")
	}
	if s.For("test/repo").Exists(wrong) {
		t.Fatal("blob was stored despite the digest mismatch")
	}
	// A failed commit must discard the session rather than leave it resumable.
	if _, err := s.UploadStatus(up.ID); err != ErrUploadClosed {
		t.Fatalf("session survived a failed commit: %v", err)
	}
}

func TestUploadRespectsMaxBytes(t *testing.T) {
	s := newTestStore(t, 8)
	up, _ := s.NewUpload()
	if _, err := s.Append(up.ID, strings.NewReader("way too much content"), 0); err != ErrTooLarge {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestUploadIDCannotEscapeDirectory(t *testing.T) {
	s := newTestStore(t, 0)
	for _, id := range []string{"../etc/passwd", "a/b", "..", ""} {
		if _, err := s.UploadStatus(id); err != ErrUploadClosed {
			t.Errorf("UploadStatus(%q) = %v, want ErrUploadClosed", id, err)
		}
	}
}

func TestDeduplicatesIdenticalBlobs(t *testing.T) {
	s := newTestStore(t, 0)
	content := []byte("shared layer")

	for i := 0; i < 2; i++ {
		up, _ := s.NewUpload()
		s.Append(up.ID, bytes.NewReader(content), 0)
		if _, err := s.For("test/repo").Commit(up.ID, digestOf(content)); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	_, count, err := s.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage: %v", err)
	}
	if count != 1 {
		t.Fatalf("blob count = %d, want 1 (content-addressed storage must dedupe)", count)
	}
}

func TestPurgeStaleUploads(t *testing.T) {
	s := newTestStore(t, 0)
	up, _ := s.NewUpload()

	// Nothing is stale yet.
	if n, _ := s.PurgeStaleUploads(time.Hour); n != 0 {
		t.Fatalf("purged %d fresh uploads, want 0", n)
	}
	// Everything is stale with a zero max age.
	if n, _ := s.PurgeStaleUploads(0); n != 1 {
		t.Fatalf("purged %d stale uploads, want 1", n)
	}
	if _, err := s.UploadStatus(up.ID); err != ErrUploadClosed {
		t.Fatal("purged upload is still resumable")
	}
}

func TestWalkBlobs(t *testing.T) {
	s := newTestStore(t, 0)
	want := map[string]bool{}
	for _, c := range []string{"one", "two", "three"} {
		d, err := s.For("test/repo").PutBytes([]byte(c))
		if err != nil {
			t.Fatalf("PutBytes: %v", err)
		}
		want[d] = true
	}
	got := map[string]bool{}
	if err := s.WalkBlobs(func(d string, _ int64) error { got[d] = true; return nil }); err != nil {
		t.Fatalf("WalkBlobs: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("walked %d blobs, want %d", len(got), len(want))
	}
	for d := range want {
		if !got[d] {
			t.Errorf("WalkBlobs missed %s", d)
		}
	}
}

// ---------------------------------------------------------------- sha512

func sha512DigestOf(b []byte) string {
	d, err := DigestWith("sha512", b)
	if err != nil {
		panic(err)
	}
	return d
}

// The distribution specification allows a client to name content with sha512.
// The upload session does not learn which algorithm will be used until the
// closing PUT, so every supported algorithm is hashed as the bytes stream in.
func TestUploadCommitWithSHA512(t *testing.T) {
	s := newTestStore(t, 0)
	content := []byte("content addressed under sha512")

	up, _ := s.NewUpload()
	if _, err := s.Append(up.ID, bytes.NewReader(content), 0); err != nil {
		t.Fatalf("Append: %v", err)
	}
	digest := sha512DigestOf(content)
	if _, err := s.For("test/repo").Commit(up.ID, digest); err != nil {
		t.Fatalf("Commit with sha512: %v", err)
	}
	got, err := s.For("test/repo").ReadAll(digest)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("sha512-addressed blob does not round-trip")
	}
}

// A chunked upload must be finalisable under either algorithm, since the
// running state for both is carried across PATCH boundaries.
func TestChunkedUploadCommitsUnderEitherAlgorithm(t *testing.T) {
	for _, algo := range []string{"sha256", "sha512"} {
		t.Run(algo, func(t *testing.T) {
			s := newTestStore(t, 0)
			content := []byte("first chunk|second chunk|third chunk")

			up, _ := s.NewUpload()
			var off int64
			for _, chunk := range [][]byte{content[:12], content[12:26], content[26:]} {
				if _, err := s.Append(up.ID, bytes.NewReader(chunk), off); err != nil {
					t.Fatalf("Append: %v", err)
				}
				off += int64(len(chunk))
			}
			want, err := DigestWith(algo, content)
			if err != nil {
				t.Fatalf("DigestWith: %v", err)
			}
			if _, err := s.For("test/repo").Commit(up.ID, want); err != nil {
				t.Fatalf("Commit under %s: %v", algo, err)
			}
			if !s.For("test/repo").Exists(want) {
				t.Fatalf("blob not stored under %s digest", algo)
			}
		})
	}
}

func TestCommitRejectsSHA512Mismatch(t *testing.T) {
	s := newTestStore(t, 0)
	up, _ := s.NewUpload()
	s.Append(up.ID, strings.NewReader("actual"), 0)

	wrong := sha512DigestOf([]byte("different"))
	if _, err := s.For("test/repo").Commit(up.ID, wrong); err == nil {
		t.Fatal("Commit accepted a mismatched sha512 digest")
	}
	if s.For("test/repo").Exists(wrong) {
		t.Fatal("blob stored under a sha512 digest that does not match its content")
	}
}

func TestZeroLengthBlob(t *testing.T) {
	s := newTestStore(t, 0)
	up, _ := s.NewUpload()
	if _, err := s.Append(up.ID, bytes.NewReader(nil), 0); err != nil {
		t.Fatalf("Append empty: %v", err)
	}
	digest := digestOf(nil)
	size, err := s.For("test/repo").Commit(up.ID, digest)
	if err != nil {
		t.Fatalf("Commit empty blob: %v", err)
	}
	if size != 0 {
		t.Fatalf("size = %d, want 0", size)
	}
	if !s.For("test/repo").Exists(digest) {
		t.Fatal("the empty blob must be storable and addressable")
	}
}
