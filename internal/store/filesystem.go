package store

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FilesystemBackend stores blobs as files under a root directory. It is the
// default, needs nothing else running, and is what a single-host deployment
// wants.
type FilesystemBackend struct {
	root string
}

func NewFilesystemBackend(root string) (*FilesystemBackend, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create %s: %w", root, err)
	}
	return &FilesystemBackend{root: root}, nil
}

func (b *FilesystemBackend) Name() string { return "filesystem(" + b.root + ")" }

// path resolves a key, refusing anything that would escape the root.
func (b *FilesystemBackend) path(key string) (string, error) {
	clean := filepath.Clean("/" + key)
	full := filepath.Join(b.root, clean)
	if !strings.HasPrefix(full, filepath.Clean(b.root)+string(os.PathSeparator)) {
		return "", fmt.Errorf("key escapes the storage root")
	}
	return full, nil
}

// Put writes to a temporary file and renames it into place, so a failed or
// interrupted write never leaves a partial object visible under the key.
func (b *FilesystemBackend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	full, err := b.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), full)
}

func (b *FilesystemBackend) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	full, err := b.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

func (b *FilesystemBackend) GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	full, err := b.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	if length <= 0 {
		return f, nil
	}
	return readCloser{Reader: io.LimitReader(f, length), Closer: f}, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

func (b *FilesystemBackend) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	full, err := b.path(key)
	if err != nil {
		return ObjectInfo{}, err
	}
	st, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return ObjectInfo{}, ErrNotFound
		}
		return ObjectInfo{}, err
	}
	return ObjectInfo{Key: key, Size: st.Size(), Modified: st.ModTime()}, nil
}

func (b *FilesystemBackend) Delete(ctx context.Context, key string) error {
	full, err := b.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (b *FilesystemBackend) Walk(ctx context.Context, prefix string, fn func(ObjectInfo) error) error {
	start := filepath.Join(b.root, filepath.Clean("/"+prefix))
	return filepath.Walk(start, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Skip the scratch files a concurrent Put may have left behind.
		if strings.HasPrefix(filepath.Base(path), ".put-") {
			return nil
		}
		rel, err := filepath.Rel(b.root, path)
		if err != nil {
			return nil
		}
		return fn(ObjectInfo{
			Key:      filepath.ToSlash(rel),
			Size:     info.Size(),
			Modified: info.ModTime(),
		})
	})
}

// LocalRoot reports the directory a filesystem backend writes to. Upload
// scratch space is always local even when blobs live elsewhere, because an
// in-progress upload is rewritten constantly and object stores charge per
// request.
func (b *FilesystemBackend) LocalRoot() string { return b.root }

var _ = time.Time{}
