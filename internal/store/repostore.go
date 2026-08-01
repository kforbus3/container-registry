package store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"
)

// A Store bound to one repository.
//
// Once blobs can live in different backends, every blob operation needs to know
// which repository it is for. Passing the name to each call would work until
// somebody forgot one, and a forgotten repository means reading from -- or
// worse, writing to -- the wrong bucket. Binding it into a handle makes the
// omission impossible to express.

// RepoStore is the blob interface for a single repository.
type RepoStore struct {
	s    *Store
	repo string
}

// For returns a handle for one repository's blobs.
func (s *Store) For(repo string) *RepoStore { return &RepoStore{s: s, repo: repo} }

// Backend reports where this repository's blobs are stored.
func (r *RepoStore) Backend() (Backend, error) {
	b, rule := r.s.router.Resolve(r.repo)
	if b == nil {
		return nil, fmt.Errorf(
			"storage rule %q for repository %q names a backend that is not configured",
			rule, r.repo)
	}
	return b, nil
}

// BackendName is the backend's identity, or a description of why there is none.
func (r *RepoStore) BackendName() string {
	b, err := r.Backend()
	if err != nil {
		return "unavailable"
	}
	return b.Name()
}

func (r *RepoStore) Exists(digest string) bool {
	key, err := blobKey(digest)
	if err != nil {
		return false
	}
	b, err := r.Backend()
	if err != nil {
		return false
	}
	_, err = b.Stat(context.Background(), key)
	return err == nil
}

func (r *RepoStore) Stat(digest string) (int64, time.Time, error) {
	key, err := blobKey(digest)
	if err != nil {
		return 0, time.Time{}, err
	}
	b, err := r.Backend()
	if err != nil {
		return 0, time.Time{}, err
	}
	info, err := b.Stat(context.Background(), key)
	if err != nil {
		return 0, time.Time{}, err
	}
	return info.Size, info.Modified, nil
}

func (r *RepoStore) Open(digest string) (io.ReadCloser, int64, error) {
	size, _, err := r.Stat(digest)
	if err != nil {
		return nil, 0, err
	}
	rc, err := r.Open2(digest)
	if err != nil {
		return nil, 0, err
	}
	return rc, size, nil
}

func (r *RepoStore) Open2(digest string) (io.ReadCloser, error) {
	key, err := blobKey(digest)
	if err != nil {
		return nil, err
	}
	b, err := r.Backend()
	if err != nil {
		return nil, err
	}
	return b.Get(context.Background(), key)
}

func (r *RepoStore) OpenRange(digest string, offset, length int64) (io.ReadCloser, error) {
	key, err := blobKey(digest)
	if err != nil {
		return nil, err
	}
	b, err := r.Backend()
	if err != nil {
		return nil, err
	}
	return b.GetRange(context.Background(), key, offset, length)
}

func (r *RepoStore) ReadAll(digest string) ([]byte, error) {
	rc, err := r.Open2(digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 64<<20))
}

func (r *RepoStore) PutBytes(b []byte) (string, error) {
	return r.PutBytesWith("sha256", b)
}

func (r *RepoStore) PutBytesWith(algo string, body []byte) (string, error) {
	digest, err := DigestWith(algo, body)
	if err != nil {
		return "", err
	}
	key, err := blobKey(digest)
	if err != nil {
		return "", err
	}
	backend, err := r.Backend()
	if err != nil {
		return "", err
	}
	if _, err := backend.Stat(context.Background(), key); err == nil {
		return digest, nil // already present; content-addressed so identical
	}
	if err := r.s.putTo(context.Background(), backend, key, bytes.NewReader(body), int64(len(body))); err != nil {
		return "", err
	}
	return digest, nil
}

// Delete removes a blob from this repository's backend.
//
// It deletes the bytes, so the caller must already have established that no
// other repository sharing this backend still references the digest.
func (r *RepoStore) Delete(digest string) error {
	key, err := blobKey(digest)
	if err != nil {
		return err
	}
	backend, err := r.Backend()
	if err != nil {
		return err
	}
	return r.s.deleteFrom(context.Background(), backend, key)
}

// Commit finalises an upload into this repository's backend.
func (r *RepoStore) Commit(id, expectedDigest string) (int64, error) {
	return r.s.commitTo(r, id, expectedDigest)
}

// BlobPath returns the on-disk path for a digest when this repository's blobs
// are local. It is meaningless for an object store and reports an error there.
func (r *RepoStore) BlobPath(digest string) (string, error) {
	backend, err := r.Backend()
	if err != nil {
		return "", err
	}
	fs, ok := backend.(*FilesystemBackend)
	if !ok {
		return "", fmt.Errorf("blobs for %s are not stored on the local filesystem", r.repo)
	}
	key, err := blobKey(digest)
	if err != nil {
		return "", err
	}
	return fs.LocalRoot() + "/" + key, nil
}
