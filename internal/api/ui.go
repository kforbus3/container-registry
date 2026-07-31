package api

import (
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
		// Assets change only on redeploy; a short cache keeps reloads cheap
		// without stranding users on a stale bundle.
		w.Header().Set("Cache-Control", "public, max-age=300")
		fileServer.ServeHTTP(w, r)
	})
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
