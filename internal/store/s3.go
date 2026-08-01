package store

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// S3Config describes an S3-compatible object store. It is deliberately generic:
// MinIO, Ceph RADOS Gateway, Backblaze B2 and Cloudflare R2 all speak this
// protocol, and only the endpoint and path style differ.
type S3Config struct {
	Endpoint     string // https://s3.us-east-1.amazonaws.com, or a MinIO address
	Region       string
	Bucket       string
	Prefix       string // optional key prefix, so one bucket can hold several registries
	AccessKey    string
	SecretKey    string
	SessionToken string
	// PathStyle addresses the bucket as a path segment rather than a subdomain,
	// which is what MinIO and most self-hosted gateways require.
	PathStyle bool
}

// S3Backend stores blobs in an S3-compatible object store.
type S3Backend struct {
	cfg  S3Config
	http *http.Client
	base *url.URL
}

// NewS3Backend validates the configuration and prepares a client. It does not
// contact the service; that happens on first use.
func NewS3Backend(cfg S3Config) (*S3Backend, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("S3 bucket is required")
	}
	if cfg.Endpoint == "" {
		if cfg.Region == "" {
			return nil, fmt.Errorf("S3 endpoint or region is required")
		}
		cfg.Endpoint = "https://s3." + cfg.Region + ".amazonaws.com"
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if !strings.Contains(cfg.Endpoint, "://") {
		cfg.Endpoint = "https://" + cfg.Endpoint
	}
	base, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid S3 endpoint: %w", err)
	}
	cfg.Prefix = strings.Trim(cfg.Prefix, "/")

	return &S3Backend{
		cfg:  cfg,
		base: base,
		http: &http.Client{
			// No overall timeout: a blob can be gigabytes and legitimately take
			// a long time. The transport still bounds connection setup.
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   32,
				ResponseHeaderTimeout: 60 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		},
	}, nil
}

func (b *S3Backend) Name() string {
	return fmt.Sprintf("s3(%s/%s)", b.cfg.Endpoint, b.cfg.Bucket)
}

// objectURL builds the request URL for a key, honouring path- or virtual-host
// style addressing.
func (b *S3Backend) objectURL(key string) *url.URL {
	u := *b.base
	full := b.prefixed(key)
	if b.cfg.PathStyle {
		u.Path = "/" + b.cfg.Bucket + "/" + full
	} else {
		u.Host = b.cfg.Bucket + "." + u.Host
		u.Path = "/" + full
	}
	// Set RawPath so the signer sees the same encoding the server will.
	u.RawPath = escapeKeyPath(u.Path)
	return &u
}

// escapeKeyPath percent-encodes a path while leaving its separators intact.
func escapeKeyPath(p string) string {
	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s, true)
	}
	return strings.Join(segments, "/")
}

func (b *S3Backend) prefixed(key string) string {
	if b.cfg.Prefix == "" {
		return key
	}
	return b.cfg.Prefix + "/" + key
}

func (b *S3Backend) sign(req *http.Request, payloadHash string) {
	signV4(req, b.cfg.AccessKey, b.cfg.SecretKey, b.cfg.SessionToken,
		b.cfg.Region, "s3", payloadHash, time.Now())
}

// do sends a signed request and turns a non-2xx response into an error, mapping
// a missing object onto ErrNotFound so callers need not know about HTTP.
func (b *S3Backend) do(req *http.Request, payloadHash string) (*http.Response, error) {
	b.sign(req, payloadHash)
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("s3 %s %s: %s: %s",
			req.Method, req.URL.Path, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

func (b *S3Backend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	// A zero-length object needs http.NoBody. Go treats a non-nil body with
	// ContentLength 0 as *unknown* length and omits the Content-Length header
	// entirely, which S3 rejects with 411. Empty blobs are not hypothetical:
	// the OCI conformance suite pushes them, and the empty-JSON descriptor used
	// by artifact manifests is two bytes away from being one.
	body := r
	if size == 0 {
		body = nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, b.objectURL(key).String(), body)
	if err != nil {
		return err
	}
	if size == 0 {
		req.Body = http.NoBody
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")

	// The body is streamed rather than hashed up front: a layer can be
	// gigabytes, and the registry verifies its digest independently anyway.
	resp, err := b.do(req, unsignedPayload)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (b *S3Backend) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.objectURL(key).String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.do(req, emptyPayload)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (b *S3Backend) GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.objectURL(key).String(), nil)
	if err != nil {
		return nil, err
	}
	if length > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	} else {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := b.do(req, emptyPayload)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (b *S3Backend) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, b.objectURL(key).String(), nil)
	if err != nil {
		return ObjectInfo{}, err
	}
	resp, err := b.do(req, emptyPayload)
	if err != nil {
		return ObjectInfo{}, err
	}
	defer resp.Body.Close()

	info := ObjectInfo{Key: key, Size: resp.ContentLength}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			info.Modified = t
		}
	}
	return info, nil
}

func (b *S3Backend) Delete(ctx context.Context, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.objectURL(key).String(), nil)
	if err != nil {
		return err
	}
	resp, err := b.do(req, emptyPayload)
	if err != nil {
		// Deleting something that is already gone is the desired end state, so
		// collection can run twice without complaining.
		if err == ErrNotFound {
			return nil
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// listBucketResult is the ListObjectsV2 response.
type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string `xml:"Key"`
		Size         int64  `xml:"Size"`
		LastModified string `xml:"LastModified"`
	} `xml:"Contents"`
}

func (b *S3Backend) Walk(ctx context.Context, prefix string, fn func(ObjectInfo) error) error {
	token := ""
	for {
		u := *b.base
		if b.cfg.PathStyle {
			u.Path = "/" + b.cfg.Bucket
		} else {
			u.Host = b.cfg.Bucket + "." + u.Host
			u.Path = "/"
		}
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("max-keys", "1000")
		if p := b.prefixed(prefix); p != "" {
			q.Set("prefix", p)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		resp, err := b.do(req, emptyPayload)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}

		var result listBucketResult
		if err := xml.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("parse bucket listing: %w", err)
		}
		for _, obj := range result.Contents {
			key := strings.TrimPrefix(obj.Key, b.cfg.Prefix+"/")
			info := ObjectInfo{Key: key, Size: obj.Size}
			if t, err := time.Parse(time.RFC3339, obj.LastModified); err == nil {
				info.Modified = t
			}
			if err := fn(info); err != nil {
				return err
			}
		}
		if !result.IsTruncated || result.NextContinuationToken == "" {
			return nil
		}
		token = result.NextContinuationToken
	}
}

// S3ConfigFromEnv reads S3 settings from the environment, reporting whether an
// object store was configured at all.
func S3ConfigFromEnv() (S3Config, bool) {
	bucket := strings.TrimSpace(os.Getenv("REGISTRY_S3_BUCKET"))
	if bucket == "" {
		return S3Config{}, false
	}
	pathStyle := true
	if v := strings.TrimSpace(os.Getenv("REGISTRY_S3_PATH_STYLE")); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			pathStyle = b
		}
	}
	return S3Config{
		Endpoint:     strings.TrimSpace(os.Getenv("REGISTRY_S3_ENDPOINT")),
		Region:       strings.TrimSpace(os.Getenv("REGISTRY_S3_REGION")),
		Bucket:       bucket,
		Prefix:       strings.TrimSpace(os.Getenv("REGISTRY_S3_PREFIX")),
		AccessKey:    os.Getenv("REGISTRY_S3_ACCESS_KEY"),
		SecretKey:    os.Getenv("REGISTRY_S3_SECRET_KEY"),
		SessionToken: os.Getenv("REGISTRY_S3_SESSION_TOKEN"),
		PathStyle:    pathStyle,
	}, true
}
