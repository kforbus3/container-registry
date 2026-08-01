package store

import (
	"context"
	"io"
	"time"
)

// Backend is where blob bytes actually live.
//
// The registry is content-addressed, so a backend only ever needs to put, get,
// stat and delete objects by an opaque key, plus enumerate them for garbage
// collection. Everything above this line — digest verification, upload
// sessions, reference counting — is backend-independent and stays in the
// registry rather than being reimplemented per backend.
type Backend interface {
	// Put stores an object. Implementations must not partially publish: a
	// reader that fails mid-stream leaves no object visible under key.
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Get opens an object for reading. Callers close it.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// GetRange opens a byte range, which is what a resumable pull needs.
	GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)
	// Stat reports an object's size and last modification.
	Stat(ctx context.Context, key string) (ObjectInfo, error)
	// Delete removes an object. A missing object is not an error, so
	// collection is idempotent.
	Delete(ctx context.Context, key string) error
	// Walk calls fn for every object under prefix.
	Walk(ctx context.Context, prefix string, fn func(ObjectInfo) error) error
	// Name identifies the backend in logs and the settings endpoint.
	Name() string
}

// ObjectInfo describes one stored object.
type ObjectInfo struct {
	Key      string
	Size     int64
	Modified time.Time
}
