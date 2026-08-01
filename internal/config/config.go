// Package config holds runtime configuration, sourced from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Addr is the listen address for the HTTP server.
	Addr string
	// DataDir holds the content-addressable blob store and upload scratch space.
	DataDir string
	// DBPath is the SQLite metadata database.
	DBPath string
	// Realm is advertised in WWW-Authenticate challenges.
	Realm string
	// MaxUploadBytes caps a single blob upload. Zero means unlimited.
	MaxUploadBytes int64
	// SessionTTL controls how long a web UI session cookie stays valid.
	SessionTTL time.Duration
	// BootstrapUser/BootstrapPassword create the first admin on an empty database.
	BootstrapUser     string
	BootstrapPassword string
	// TLSCert and TLSKey enable HTTPS when both are set.
	TLSCert string
	TLSKey  string
	// AllowAnonymousPull serves GETs on /v2 without credentials.
	AllowAnonymousPull bool
	// GCGrace protects blobs written more recently than this from collection,
	// so a push in flight is never broken by a concurrent sweep.
	GCGrace time.Duration
	// GCUploadTTL bounds how long an abandoned upload session is retained.
	GCUploadTTL time.Duration
	// SBOMEnabled turns on automatic SBOM generation for pushed images.
	SBOMEnabled bool
	// SBOMWorkers is how many images may be scanned concurrently.
	SBOMWorkers int
	// SBOMQueueDepth bounds the backlog of images awaiting a scan.
	SBOMQueueDepth int
	// VulnEnabled turns on matching each SBOM against an advisory database.
	VulnEnabled bool
	// VulnEndpoint is the OSV-compatible API to query. Point it at a mirror to
	// run without egress to the public service.
	VulnEndpoint string
	// VulnWorkers and VulnQueueDepth size the scan worker pool.
	VulnWorkers    int
	VulnQueueDepth int
	// VulnTimeout bounds a single request to the advisory service.
	VulnTimeout time.Duration
	// VulnAdvisoryTTL is how long a cached advisory is reused before refetch.
	VulnAdvisoryTTL time.Duration
}

func Load() (*Config, error) {
	c := &Config{
		Addr:               env("REGISTRY_ADDR", ":5000"),
		DataDir:            env("REGISTRY_DATA_DIR", "./data"),
		Realm:              env("REGISTRY_REALM", "container-registry"),
		BootstrapUser:      env("REGISTRY_ADMIN_USER", "admin"),
		BootstrapPassword:  os.Getenv("REGISTRY_ADMIN_PASSWORD"),
		TLSCert:            os.Getenv("REGISTRY_TLS_CERT"),
		TLSKey:             os.Getenv("REGISTRY_TLS_KEY"),
		AllowAnonymousPull: envBool("REGISTRY_ANONYMOUS_PULL", false),
		SBOMEnabled:        envBool("REGISTRY_SBOM", true),
		SBOMWorkers:        envInt("REGISTRY_SBOM_WORKERS", 2),
		SBOMQueueDepth:     envInt("REGISTRY_SBOM_QUEUE", 256),
		VulnEnabled:        envBool("REGISTRY_VULN_SCAN", true),
		VulnEndpoint:       env("REGISTRY_VULN_ENDPOINT", "https://api.osv.dev"),
		VulnWorkers:        envInt("REGISTRY_VULN_WORKERS", 2),
		VulnQueueDepth:     envInt("REGISTRY_VULN_QUEUE", 256),
	}
	c.DBPath = env("REGISTRY_DB_PATH", c.DataDir+"/registry.db")

	var err error
	if c.MaxUploadBytes, err = envBytes("REGISTRY_MAX_UPLOAD_BYTES", 0); err != nil {
		return nil, err
	}
	if c.SessionTTL, err = envDuration("REGISTRY_SESSION_TTL", 12*time.Hour); err != nil {
		return nil, err
	}
	if c.GCGrace, err = envDuration("REGISTRY_GC_GRACE", time.Hour); err != nil {
		return nil, err
	}
	if c.GCUploadTTL, err = envDuration("REGISTRY_GC_UPLOAD_TTL", 24*time.Hour); err != nil {
		return nil, err
	}
	if c.VulnTimeout, err = envDuration("REGISTRY_VULN_TIMEOUT", 60*time.Second); err != nil {
		return nil, err
	}
	if c.VulnAdvisoryTTL, err = envDuration("REGISTRY_VULN_ADVISORY_TTL", 24*time.Hour); err != nil {
		return nil, err
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, fmt.Errorf("REGISTRY_TLS_CERT and REGISTRY_TLS_KEY must be set together")
	}
	return c, nil
}

func (c *Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func envBytes(key string, def int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
