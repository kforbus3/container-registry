// Package store implements the on-disk content-addressable blob store and the
// resumable upload sessions the OCI distribution spec requires.
//
// Layout under root:
//
//	blobs/sha256/<aa>/<full-hex>      blob content, named by its own digest
//	uploads/<uuid>.data               in-progress upload body
//	uploads/<uuid>.state              serialised SHA-256 state + offset
package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound     = errors.New("blob not found")
	ErrBadDigest    = errors.New("digest mismatch")
	ErrBadOffset    = errors.New("upload offset mismatch")
	ErrUploadClosed = errors.New("upload not found")
	ErrTooLarge     = errors.New("upload exceeds maximum size")
)

type Store struct {
	// root is local scratch space. Upload sessions always live here, even when
	// blobs are stored elsewhere: an in-progress upload is appended to and
	// re-read constantly, and object stores charge per request.
	root     string
	maxBytes int64
	backend  Backend

	// mu guards concurrent PATCHes against the same upload session. The spec
	// forbids them, but a buggy client must not corrupt the hash state.
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// New creates a store backed by the local filesystem.
func New(root string, maxBytes int64) (*Store, error) {
	fs, err := NewFilesystemBackend(filepath.Join(root, "blobs"))
	if err != nil {
		return nil, err
	}
	return NewWithBackend(root, maxBytes, fs)
}

// NewWithBackend creates a store whose blobs live in the given backend, using
// root only for upload scratch space.
func NewWithBackend(root string, maxBytes int64, backend Backend) (*Store, error) {
	for _, d := range []string{root, filepath.Join(root, "uploads")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
	}
	return &Store{
		root: root, maxBytes: maxBytes, backend: backend,
		locks: map[string]*sync.Mutex{},
	}, nil
}

func (s *Store) Root() string { return s.root }

// Backend reports where blobs are stored, for logs and the settings endpoint.
func (s *Store) Backend() string { return s.backend.Name() }

// blobKey is the backend key for a digest. The two-character fan-out keeps
// filesystem directories manageable and gives object stores a well-distributed
// key space.
func blobKey(digest string) (string, error) {
	algo, h, err := ParseDigest(digest)
	if err != nil {
		return "", err
	}
	return algo + "/" + h[:2] + "/" + h, nil
}

// ---------------------------------------------------------------- digests

// ParseDigest validates an algorithm-prefixed digest string and returns its
// algorithm and hex portion.
func ParseDigest(d string) (algo, hexPart string, err error) {
	i := strings.IndexByte(d, ':')
	if i <= 0 {
		return "", "", fmt.Errorf("malformed digest %q", d)
	}
	algo, hexPart = d[:i], d[i+1:]
	switch algo {
	case "sha256":
		if len(hexPart) != 64 {
			return "", "", fmt.Errorf("sha256 digest must be 64 hex chars")
		}
	case "sha512":
		if len(hexPart) != 128 {
			return "", "", fmt.Errorf("sha512 digest must be 128 hex chars")
		}
	default:
		return "", "", fmt.Errorf("unsupported digest algorithm %q", algo)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", "", fmt.Errorf("digest is not valid hex")
	}
	return algo, strings.ToLower(hexPart), nil
}

func ValidDigest(d string) bool {
	_, _, err := ParseDigest(d)
	return err == nil
}

// Digest computes the sha256 digest string of b. sha256 is the algorithm the
// distribution specification requires every registry to support, so it is the
// default for content the registry names itself.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestWith computes the digest of b under the named algorithm. It is used
// when a client addresses content with something other than sha256.
func DigestWith(algo string, b []byte) (string, error) {
	h, err := hasherFor(algo)
	if err != nil {
		return "", err
	}
	h.Write(b)
	return algo + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

// SupportedAlgorithms lists the digest algorithms the registry accepts.
var SupportedAlgorithms = []string{"sha256", "sha512"}

func hasherFor(algo string) (hash.Hash, error) {
	switch algo {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", algo)
	}
}

// DigestAlgorithm returns the algorithm portion of a digest string.
func DigestAlgorithm(d string) string {
	algo, _, err := ParseDigest(d)
	if err != nil {
		return ""
	}
	return algo
}

// BlobPath returns the on-disk path for a digest when blobs are stored
// locally. It is meaningless for an object store and reports an error there.
func (s *Store) BlobPath(digest string) (string, error) {
	fs, ok := s.backend.(*FilesystemBackend)
	if !ok {
		return "", fmt.Errorf("blobs are not stored on the local filesystem")
	}
	key, err := blobKey(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(fs.LocalRoot(), filepath.FromSlash(key)), nil
}

// ---------------------------------------------------------------- blob reads

func (s *Store) Exists(digest string) bool {
	key, err := blobKey(digest)
	if err != nil {
		return false
	}
	_, err = s.backend.Stat(context.Background(), key)
	return err == nil
}

func (s *Store) Stat(digest string) (int64, time.Time, error) {
	key, err := blobKey(digest)
	if err != nil {
		return 0, time.Time{}, err
	}
	info, err := s.backend.Stat(context.Background(), key)
	if err != nil {
		return 0, time.Time{}, err
	}
	return info.Size, info.Modified, nil
}

// Open returns a reader for a blob plus its size.
func (s *Store) Open(digest string) (io.ReadCloser, int64, error) {
	key, err := blobKey(digest)
	if err != nil {
		return nil, 0, err
	}
	info, err := s.backend.Stat(context.Background(), key)
	if err != nil {
		return nil, 0, err
	}
	rc, err := s.backend.Get(context.Background(), key)
	if err != nil {
		return nil, 0, err
	}
	return rc, info.Size, nil
}

// Open2 returns just a reader for a blob, for callers that already know the size.
func (s *Store) Open2(digest string) (io.ReadCloser, error) {
	key, err := blobKey(digest)
	if err != nil {
		return nil, err
	}
	return s.backend.Get(context.Background(), key)
}

// OpenRange returns a reader for part of a blob, which is what a ranged pull
// needs. length <= 0 reads to the end.
func (s *Store) OpenRange(digest string, offset, length int64) (io.ReadCloser, error) {
	key, err := blobKey(digest)
	if err != nil {
		return nil, err
	}
	return s.backend.GetRange(context.Background(), key, offset, length)
}

// ReadAll loads a whole blob into memory. Only used for manifests, which are
// bounded well under a megabyte.
func (s *Store) ReadAll(digest string) ([]byte, error) {
	key, err := blobKey(digest)
	if err != nil {
		return nil, err
	}
	rc, err := s.backend.Get(context.Background(), key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// Manifests and configs are the only things read whole, and both are
	// bounded well under this.
	return io.ReadAll(io.LimitReader(rc, 64<<20))
}

// PutBytes stores b under its own sha256 digest and returns that digest.
func (s *Store) PutBytes(b []byte) (string, error) {
	return s.PutBytesWith("sha256", b)
}

// PutBytesWith stores b under its digest in the named algorithm. Content
// addressed under two algorithms is stored twice, which is the price of
// letting a client choose how it names things.
func (s *Store) PutBytesWith(algo string, b []byte) (string, error) {
	digest, err := DigestWith(algo, b)
	if err != nil {
		return "", err
	}
	key, err := blobKey(digest)
	if err != nil {
		return "", err
	}
	if _, err := s.backend.Stat(context.Background(), key); err == nil {
		return digest, nil // already present; content-addressed so identical
	}
	if err := s.backend.Put(context.Background(), key, bytes.NewReader(b), int64(len(b))); err != nil {
		return "", err
	}
	return digest, nil
}

// Delete removes a blob from the content store. Missing blobs are not an error.
func (s *Store) Delete(digest string) error {
	key, err := blobKey(digest)
	if err != nil {
		return err
	}
	return s.backend.Delete(context.Background(), key)
}

// ---------------------------------------------------------------- uploads

type uploadState struct {
	ID     string `json:"id"`
	Offset int64  `json:"offset"`
	// HashStates holds one serialised hash per supported algorithm, keyed by
	// algorithm name. The digest a client will finalise with is not known until
	// the closing PUT, so every candidate is computed as the bytes stream in —
	// far cheaper than re-reading a multi-gigabyte layer to hash it again.
	HashStates map[string][]byte `json:"hash_states"`
	StartedAt  time.Time         `json:"started_at"`
}

// Upload is the caller-visible view of an in-progress upload session.
type Upload struct {
	ID        string
	Offset    int64
	StartedAt time.Time
}

func newUploadID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// UUIDv4 shape; the spec only requires an opaque, unguessable identifier.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (s *Store) uploadPaths(id string) (data, state string, err error) {
	// The id goes into a path, so reject anything that could escape the dir.
	if id == "" || strings.ContainsAny(id, "/\\.") {
		return "", "", ErrUploadClosed
	}
	base := filepath.Join(s.root, "uploads", id)
	return base + ".data", base + ".state", nil
}

func (s *Store) lockFor(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.locks[id]
	if !ok {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	return m
}

func (s *Store) unlockFor(id string) {
	s.mu.Lock()
	delete(s.locks, id)
	s.mu.Unlock()
}

// NewUpload begins a resumable upload session.
func (s *Store) NewUpload() (*Upload, error) {
	id, err := newUploadID()
	if err != nil {
		return nil, err
	}
	data, _, err := s.uploadPaths(id)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(data, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	f.Close()

	st := &uploadState{ID: id, StartedAt: time.Now().UTC(), HashStates: map[string][]byte{}}
	for _, algo := range SupportedAlgorithms {
		h, err := hasherFor(algo)
		if err != nil {
			return nil, err
		}
		if st.HashStates[algo], err = h.(encoding.BinaryMarshaler).MarshalBinary(); err != nil {
			return nil, err
		}
	}
	if err := s.saveState(st); err != nil {
		return nil, err
	}
	return &Upload{ID: id, Offset: 0, StartedAt: st.StartedAt}, nil
}

func (s *Store) saveState(st *uploadState) error {
	_, statePath, err := s.uploadPaths(st.ID)
	if err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, statePath)
}

func (s *Store) loadState(id string) (*uploadState, error) {
	_, statePath, err := s.uploadPaths(id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUploadClosed
		}
		return nil, err
	}
	var st uploadState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// restoreHashes rebuilds every running hash from the persisted session state.
func (s *Store) restoreHashes(st *uploadState) (map[string]hash.Hash, error) {
	out := make(map[string]hash.Hash, len(st.HashStates))
	for _, algo := range SupportedAlgorithms {
		h, err := hasherFor(algo)
		if err != nil {
			return nil, err
		}
		blob, ok := st.HashStates[algo]
		if !ok {
			// A session started before this algorithm was supported cannot be
			// finalised under it; the others still work.
			continue
		}
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(blob); err != nil {
			return nil, fmt.Errorf("restore %s state: %w", algo, err)
		}
		out[algo] = h
	}
	return out, nil
}

// marshalHashes serialises the running hashes back into the session state.
func marshalHashes(hashes map[string]hash.Hash) (map[string][]byte, error) {
	out := make(map[string][]byte, len(hashes))
	for algo, h := range hashes {
		b, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			return nil, err
		}
		out[algo] = b
	}
	return out, nil
}

// UploadStatus reports the current committed offset of a session.
func (s *Store) UploadStatus(id string) (*Upload, error) {
	st, err := s.loadState(id)
	if err != nil {
		return nil, err
	}
	return &Upload{ID: st.ID, Offset: st.Offset, StartedAt: st.StartedAt}, nil
}

// Append writes r to the end of the upload. If expectedOffset is non-negative
// it must match the session's current offset (chunked upload with Content-Range).
func (s *Store) Append(id string, r io.Reader, expectedOffset int64) (*Upload, error) {
	mu := s.lockFor(id)
	mu.Lock()
	defer mu.Unlock()

	st, err := s.loadState(id)
	if err != nil {
		return nil, err
	}
	if expectedOffset >= 0 && expectedOffset != st.Offset {
		return nil, ErrBadOffset
	}
	dataPath, _, err := s.uploadPaths(id)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(dataPath, os.O_WRONLY, 0o640)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUploadClosed
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(st.Offset, io.SeekStart); err != nil {
		return nil, err
	}
	hashes, err := s.restoreHashes(st)
	if err != nil {
		return nil, err
	}
	sinks := []io.Writer{f}
	for _, algo := range SupportedAlgorithms {
		if h, ok := hashes[algo]; ok {
			sinks = append(sinks, h)
		}
	}

	src := r
	if s.maxBytes > 0 {
		// +1 so we can distinguish "exactly at the cap" from "over the cap".
		src = io.LimitReader(r, s.maxBytes-st.Offset+1)
	}
	n, err := io.Copy(io.MultiWriter(sinks...), src)
	if err != nil {
		// Persist whatever landed so the client can resume from a true offset.
		st.Offset += n
		if hs, mErr := marshalHashes(hashes); mErr == nil {
			st.HashStates = hs
		}
		f.Sync()
		s.saveState(st)
		return nil, err
	}
	st.Offset += n
	if s.maxBytes > 0 && st.Offset > s.maxBytes {
		return nil, ErrTooLarge
	}
	if st.HashStates, err = marshalHashes(hashes); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := s.saveState(st); err != nil {
		return nil, err
	}
	return &Upload{ID: st.ID, Offset: st.Offset, StartedAt: st.StartedAt}, nil
}

// Commit finalises an upload, verifying it hashes to expectedDigest, and moves
// it into the content store. The session is removed either way.
func (s *Store) Commit(id, expectedDigest string) (int64, error) {
	mu := s.lockFor(id)
	mu.Lock()
	defer func() {
		mu.Unlock()
		s.unlockFor(id)
	}()

	st, err := s.loadState(id)
	if err != nil {
		return 0, err
	}
	hashes, err := s.restoreHashes(st)
	if err != nil {
		return 0, err
	}
	algo, wantHex, err := ParseDigest(expectedDigest)
	if err != nil {
		return 0, err
	}
	h, ok := hashes[algo]
	if !ok {
		return 0, fmt.Errorf("%w: no running %s digest for this upload", ErrBadDigest, algo)
	}
	gotHex := hex.EncodeToString(h.Sum(nil))
	if gotHex != wantHex {
		s.discard(id)
		return 0, fmt.Errorf("%w: computed %s:%s", ErrBadDigest, algo, gotHex)
	}

	dataPath, statePath, err := s.uploadPaths(id)
	if err != nil {
		return 0, err
	}
	key, err := blobKey(expectedDigest)
	if err != nil {
		return 0, err
	}
	if _, err := s.backend.Stat(context.Background(), key); err == nil {
		// Already present with identical content; drop the duplicate.
		os.Remove(dataPath)
		os.Remove(statePath)
		return st.Offset, nil
	}

	f, err := os.Open(dataPath)
	if err != nil {
		return 0, err
	}
	err = s.backend.Put(context.Background(), key, f, st.Offset)
	f.Close()
	if err != nil {
		return 0, err
	}
	os.Remove(dataPath)
	os.Remove(statePath)
	return st.Offset, nil
}

// Cancel aborts an upload session and deletes its scratch files.
func (s *Store) Cancel(id string) error {
	mu := s.lockFor(id)
	mu.Lock()
	defer func() {
		mu.Unlock()
		s.unlockFor(id)
	}()
	if _, err := s.loadState(id); err != nil {
		return err
	}
	s.discard(id)
	return nil
}

func (s *Store) discard(id string) {
	if data, state, err := s.uploadPaths(id); err == nil {
		os.Remove(data)
		os.Remove(state)
	}
}

// PurgeStaleUploads removes upload sessions older than maxAge and returns the
// number removed. Called periodically and by the admin GC endpoint.
func (s *Store) PurgeStaleUploads(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, "uploads"))
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-maxAge)
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".state") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".state")
		st, err := s.loadState(id)
		if err != nil {
			continue
		}
		if st.StartedAt.Before(cutoff) {
			s.discard(id)
			n++
		}
	}
	return n, nil
}

// WalkBlobs calls fn for every blob in the content store.
func (s *Store) WalkBlobs(fn func(digest string, size int64) error) error {
	return s.backend.Walk(context.Background(), "", func(info ObjectInfo) error {
		parts := strings.Split(info.Key, "/")
		if len(parts) != 3 {
			return nil
		}
		digest := parts[0] + ":" + parts[2]
		if !ValidDigest(digest) {
			return nil
		}
		return fn(digest, info.Size)
	})
}

// DiskUsage sums the size of every blob on disk.
func (s *Store) DiskUsage() (int64, int, error) {
	var total int64
	var count int
	err := s.WalkBlobs(func(_ string, size int64) error {
		total += size
		count++
		return nil
	})
	return total, count, err
}
