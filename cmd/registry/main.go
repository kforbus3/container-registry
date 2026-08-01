// Command registry runs an OCI-compliant container registry with a token API
// and a web management UI.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kforbus3/container-registry/internal/api"
	"github.com/kforbus3/container-registry/internal/auth"
	"github.com/kforbus3/container-registry/internal/config"
	"github.com/kforbus3/container-registry/internal/db"
	"github.com/kforbus3/container-registry/internal/gc"
	"github.com/kforbus3/container-registry/internal/proxy"
	"github.com/kforbus3/container-registry/internal/ratelimit"
	"github.com/kforbus3/container-registry/internal/sbom"
	"github.com/kforbus3/container-registry/internal/store"
	"github.com/kforbus3/container-registry/internal/vuln"
	"github.com/kforbus3/container-registry/internal/webhook"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer database.Close()

	// Blobs live in an object store when one is configured, and on local disk
	// otherwise. Upload scratch space stays local either way.
	st, err := openStore(context.Background(), database, cfg, log)
	if err != nil {
		return err
	}

	if err := bootstrapAdmin(context.Background(), database, cfg, log); err != nil {
		return err
	}

	// Load the certificate before announcing anything. Left to ListenAndServeTLS
	// this fails after the "listening" line, which reads as a server that came
	// up and then died rather than one that never started.
	if cfg.TLSEnabled() {
		if _, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey); err != nil {
			return fmt.Errorf("TLS is configured but the key pair could not be loaded "+
				"(cert %q, key %q): %w", cfg.TLSCert, cfg.TLSKey, err)
		}
	}

	collector := gc.New(database, st, log)
	collector.Grace = cfg.GCGrace
	collector.UploadTTL = cfg.GCUploadTTL

	srv := api.NewServer(cfg, database, st, log)
	srv.SetCollector(collector)
	if cfg.ProxyRemote != "" {
		srv.SetUpstream(proxy.NewUpstream(
			cfg.ProxyRemote, cfg.ProxyUsername, cfg.ProxyPassword, cfg.ProxyTimeout))
		log.Info("pull-through cache enabled",
			"upstream", cfg.ProxyRemote, "prefix", cfg.ProxyPrefix,
			"authenticated", cfg.ProxyUsername != "")
	}
	srv.SetRateLimits(
		ratelimit.Limit{PerMinute: cfg.RateLimit, Burst: cfg.RateBurst},
		ratelimit.Limit{PerMinute: writeLimit(cfg), Burst: cfg.RateBurst},
	)
	if cfg.RateLimit > 0 || cfg.RateLimitWrites > 0 {
		log.Info("rate limiting enabled",
			"reads_per_minute", cfg.RateLimit,
			"writes_per_minute", writeLimit(cfg), "burst", cfg.RateBurst)
	}

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
		// Blob uploads can be large and slow, so no global write timeout; the
		// read header timeout still protects against slowloris connections.
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slogErrorLog(log),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Webhooks are started first so everything below can emit into them.
	var hooks *webhook.Dispatcher
	if cfg.WebhooksEnabled {
		hooks = webhook.New(database, log, cfg.WebhookQueue, cfg.WebhookTimeout)
		hooks.Start(ctx, cfg.WebhookWorkers)
		srv.SetWebhooks(hooks)
		defer hooks.Wait()
		log.Info("webhooks enabled", "workers", cfg.WebhookWorkers)
	}

	// Vulnerability scanning consumes the SBOMs, so it is started first and
	// chained to the generator below.
	var scanner *vuln.Scanner
	if cfg.VulnEnabled {
		scanner = vuln.New(database, st,
			vuln.NewClient(cfg.VulnEndpoint, cfg.VulnTimeout), log, cfg.VulnQueueDepth)
		scanner.AdvisoryTTL = cfg.VulnAdvisoryTTL
		if hooks != nil {
			// A completed scan is the event people actually want to gate on.
			scanner.OnComplete = func(repoID int64, repoName, digest string, critical, high int) {
				hooks.Emit(webhook.Event{
					Event: db.EventScanComplete, RepoID: repoID,
					Repository: repoName, Digest: digest, Actor: "registry",
					Data: map[string]any{"critical": critical, "high": high},
				})
			}
		}
		scanner.Start(ctx, cfg.VulnWorkers)
		srv.SetVulnScanner(scanner)
		defer scanner.Wait()
		log.Info("vulnerability scanning enabled",
			"endpoint", cfg.VulnEndpoint, "workers", cfg.VulnWorkers)
	}

	// Automatic SBOM generation. Workers run for the life of the process and
	// drain on shutdown.
	if cfg.SBOMEnabled {
		generator := sbom.New(database, st, log, cfg.SBOMWorkers, cfg.SBOMQueueDepth)
		if scanner != nil {
			// A new bill of materials is exactly when its packages should be
			// checked, so the scan follows publication rather than polling.
			generator.OnPublished = func(job sbom.Job) {
				scanner.Enqueue(vuln.Job{
					RepoID: job.RepoID, RepoName: job.RepoName, Digest: job.Digest,
				})
			}
		}
		generator.Start(ctx, cfg.SBOMWorkers)
		srv.SetSBOMGenerator(generator)
		defer generator.Wait()
		log.Info("automatic SBOM generation enabled",
			"workers", cfg.SBOMWorkers, "queue", cfg.SBOMQueueDepth)
	}

	// Retention decides what is no longer wanted; collection frees it. Running
	// them on a schedule is what stops storage growing without bound.
	scheduler := &gc.Scheduler{
		DB:           database,
		Retention:    &gc.Retention{DB: database},
		Collector:    collector,
		Log:          log,
		Interval:     cfg.MaintenanceInterval,
		InitialDelay: cfg.MaintenanceDelay,
		// Past this the advisory would be refetched anyway, so an unreferenced
		// one is not worth the several kilobytes its document occupies.
		AdvisoryTTL: cfg.VulnAdvisoryTTL,
	}
	srv.SetScheduler(scheduler)
	go scheduler.Run(ctx)

	go janitor(ctx, database, st, cfg.GCUploadTTL, log)

	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if cfg.TLSEnabled() {
			scheme = "https"
		}
		log.Info("registry listening",
			"addr", cfg.Addr, "scheme", scheme, "data_dir", cfg.DataDir,
			"anonymous_pull", cfg.AllowAnonymousPull)

		var err error
		if cfg.TLSEnabled() {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// writeLimit falls back to the general limit when no separate write limit is
// configured, so setting one number still protects the expensive path.
func writeLimit(cfg *config.Config) int {
	if cfg.RateLimitWrites > 0 {
		return cfg.RateLimitWrites
	}
	return cfg.RateLimit
}

// openStore builds the blob store.
//
// The environment wins where it is set: a REGISTRY_S3_* value in a unit file is
// what its author expects to be in force, and a value quietly overridden from a
// web form is a bad surprise during an incident. Only when the environment is
// silent does the configuration saved through the UI apply.
func openStore(ctx context.Context, database *db.DB, cfg *config.Config, log *slog.Logger) (*store.Store, error) {
	if s3cfg, ok := store.S3ConfigFromEnv(); ok {
		backend, err := store.NewS3Backend(s3cfg)
		if err != nil {
			return nil, fmt.Errorf("configure S3 storage: %w", err)
		}
		log.Info("using object storage for blobs", "source", "environment",
			"endpoint", s3cfg.Endpoint, "bucket", s3cfg.Bucket,
			"prefix", s3cfg.Prefix, "path_style", s3cfg.PathStyle)
		return store.NewWithBackend(cfg.DataDir, cfg.MaxUploadBytes, backend)
	}

	saved, ok := store.ParsePersisted(database.GetSetting(ctx, api.StorageSettingKey, ""))
	if !ok || saved.Kind != "s3" {
		return store.New(cfg.DataDir, cfg.MaxUploadBytes)
	}
	key, err := store.ConfigKey(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("read storage config key: %w", err)
	}
	s3cfg, err := saved.S3(key)
	if err != nil {
		// Refusing to start would strand the registry on an unreadable
		// credential; falling back to local disk would silently serve 404 for
		// every blob in the bucket. Neither is good, so say exactly what is
		// wrong and stop.
		return nil, fmt.Errorf("stored S3 configuration could not be read: %w", err)
	}
	backend, err := store.NewS3Backend(s3cfg)
	if err != nil {
		return nil, fmt.Errorf("configure saved S3 storage: %w", err)
	}
	log.Info("using object storage for blobs", "source", "saved configuration",
		"endpoint", s3cfg.Endpoint, "bucket", s3cfg.Bucket,
		"prefix", s3cfg.Prefix, "path_style", s3cfg.PathStyle)
	return store.NewWithBackend(cfg.DataDir, cfg.MaxUploadBytes, backend)
}

func logLevel() slog.Level {
	switch os.Getenv("REGISTRY_LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// bootstrapAdmin creates the first administrator when the database is empty.
// The password comes from REGISTRY_ADMIN_PASSWORD, or is generated and printed
// once so a fresh deployment is never left with a guessable default.
func bootstrapAdmin(ctx context.Context, database *db.DB, cfg *config.Config, log *slog.Logger) error {
	n, err := database.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	password := cfg.BootstrapPassword
	generated := false
	if password == "" {
		if password, err = auth.NewSecret(18); err != nil {
			return err
		}
		generated = true
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("bootstrap password rejected: %w", err)
	}
	if _, err := database.CreateUser(ctx, cfg.BootstrapUser, hash, "admin"); err != nil {
		return fmt.Errorf("create bootstrap admin: %w", err)
	}
	if generated {
		fmt.Printf("\n  Created administrator %q with a generated password:\n\n      %s\n\n"+
			"  This is shown once. Set REGISTRY_ADMIN_PASSWORD to choose your own.\n\n",
			cfg.BootstrapUser, password)
	} else {
		log.Info("created bootstrap administrator", "username", cfg.BootstrapUser)
	}
	return nil
}

// janitor periodically clears expired sessions and abandoned upload sessions.
func janitor(ctx context.Context, database *db.DB, st *store.Store, uploadTTL time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := database.PurgeExpiredSessions(ctx); err != nil {
				log.Warn("purge sessions failed", "err", err)
			}
			if n, err := st.PurgeStaleUploads(uploadTTL); err != nil {
				log.Warn("purge uploads failed", "err", err)
			} else if n > 0 {
				log.Info("purged abandoned uploads", "count", n)
			}
		}
	}
}
