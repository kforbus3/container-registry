package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kforbus3/container-registry/internal/config"
)

// TestAssetsRevalidateRatherThanExpire covers the caching of UI assets. A
// max-age cache meant that for its duration after an upgrade the browser kept
// serving the previous bundle: a shipped UI fix looked like it had not
// deployed, and could run against an API that had already changed.
func TestAssetsRevalidateRatherThanExpire(t *testing.T) {
	s := &Server{Cfg: &config.Config{}}
	h := s.uiHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /app.js = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache: a timed cache serves a stale UI after an upgrade", got)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag, so every reload must transfer the whole asset")
	}

	// The point of the ETag: a reload costs a 304 with no body.
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Errorf("conditional GET = %d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 carried %d bytes of body", rec2.Body.Len())
	}

	// Different assets must not share an identity.
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/style.css", nil))
	if rec3.Header().Get("ETag") == etag {
		t.Error("style.css and app.js share an ETag")
	}
}
