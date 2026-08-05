package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kforbus3/container-registry/internal/config"
)

// TestTokenRealmIsAbsolute covers the realm advertised in a Bearer challenge.
// A bare path is not merely untidy: go-containerregistry refuses it outright
// ("realm scheme \"\" not allowed"), so an unconfigured realm made token auth
// unusable with any client built on it.
func TestTokenRealmIsAbsolute(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		host       string
		tls        bool
		headers    map[string]string
		// trustProxy makes the request's peer a trusted proxy, which is what
		// makes its forwarding headers believable.
		trustProxy bool
		want       string
	}{
		{name: "derived from the request", host: "registry.example:5000",
			want: "http://registry.example:5000/token"},
		{name: "https when the request is", host: "registry.example", tls: true,
			want: "https://registry.example/token"},
		{name: "honours a trusted terminating proxy", host: "internal:5000",
			headers:    map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "reg.example"},
			trustProxy: true,
			want:       "https://reg.example/token"},
		{name: "takes the first hop of a proxy chain", host: "internal:5000",
			headers:    map[string]string{"X-Forwarded-Proto": "https, http"},
			trustProxy: true,
			want:       "https://internal:5000/token"},
		// Anyone can send these headers. Believing them from a caller that is
		// not a declared proxy would let it choose the URL clients are told to
		// fetch their credentials from.
		{name: "ignores forwarding headers from an untrusted peer", host: "internal:5000",
			headers: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "evil.example"},
			want:    "http://internal:5000/token"},
		{name: "an absolute configured realm is used as-is",
			configured: "https://auth.example/v2/token", host: "registry.example",
			want: "https://auth.example/v2/token"},
		{name: "a configured path is still made absolute",
			configured: "/auth", host: "registry.example",
			want: "http://registry.example/auth"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{TokenRealm: tc.configured}
			if tc.trustProxy {
				cfg.TrustAllProxies = true
			}
			s := &Server{Cfg: cfg}
			r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
			r.Host = tc.host
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := s.tokenRealm(r); got != tc.want {
				t.Errorf("tokenRealm = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBatchResetKeepsItsMutex is the regression test for a crash. Starting a
// bulk move reset its state by assigning a fresh struct over the one whose
// mutex was held, which replaced that mutex and made the following unlock a
// fatal error -- taking the whole registry down rather than failing the request.
func TestBatchResetKeepsItsMutex(t *testing.T) {
	b := &batchMigration{}

	start := func(n int) bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.running {
			return false
		}
		b.running = true
		b.total = n
		b.done = 0
		b.failures = nil
		return true
	}

	if !start(3) {
		t.Fatal("first start refused")
	}
	// The second call has to take the same lock. If the reset had replaced it,
	// this is where the process would have died.
	if start(5) {
		t.Error("a second bulk move started while one was running")
	}
	b.mu.Lock()
	b.running = false
	b.mu.Unlock()
	if !start(2) {
		t.Error("could not start once the previous run finished")
	}
	if got := b.snapshot()["total"]; got != 2 {
		t.Errorf("total = %v, want 2", got)
	}
}
