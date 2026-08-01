package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/kforbus3/container-registry/web"
)

// uiHandler serves the embedded single-page management UI. Unknown paths fall
// back to index.html so client-side routing works on a hard refresh.
func (s *Server) uiHandler() http.Handler {
	assets, err := fs.Sub(web.Files, ".")
	if err != nil {
		// The assets are embedded at build time; a failure here is a bug.
		panic("embedded UI assets unavailable: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(assets))
	start := time.Now()
	etags := assetETags(assets)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			s.serveIndex(w, r, assets, start)
			return
		}
		if _, err := fs.Stat(assets, clean); err != nil {
			s.serveIndex(w, r, assets, start)
			return
		}
		// "no-cache" means revalidate before use, not "do not store". A
		// timed cache was worse than it looked: for its duration after an
		// upgrade the browser kept serving the previous bundle, so a UI fix
		// appeared not to have deployed and could run against an API that had
		// already moved on. Revalidating costs one conditional request and
		// answers 304 with no body, and ServeContent handles If-None-Match
		// from the ETag set here.
		if tag, ok := etags[clean]; ok {
			w.Header().Set("ETag", tag)
		}
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
}

// assetETags hashes every embedded asset once at start-up. The files are fixed
// at build time, so the digest is a stable identity for this build and changes
// exactly when the asset does.
func assetETags(assets fs.FS) map[string]string {
	out := map[string]string{}
	fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(assets, path)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(b)
		out[path] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	return out
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request, assets fs.FS, modtime time.Time) {
	f, err := assets.Open("index.html")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "UI is unavailable")
		return
	}
	defer f.Close()
	rs, ok := f.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	})
	if !ok {
		writeErr(w, http.StatusInternalServerError, "UI is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", modtime, rs)
}
