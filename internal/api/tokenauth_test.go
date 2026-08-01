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
		want       string
	}{
		{name: "derived from the request", host: "registry.example:5000",
			want: "http://registry.example:5000/token"},
		{name: "https when the request is", host: "registry.example", tls: true,
			want: "https://registry.example/token"},
		{name: "honours a terminating proxy", host: "internal:5000",
			headers: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "reg.example"},
			want:    "https://reg.example/token"},
		{name: "takes the first hop of a proxy chain", host: "internal:5000",
			headers: map[string]string{"X-Forwarded-Proto": "https, http"},
			want:    "https://internal:5000/token"},
		{name: "an absolute configured realm is used as-is",
			configured: "https://auth.example/v2/token", host: "registry.example",
			want: "https://auth.example/v2/token"},
		{name: "a configured path is still made absolute",
			configured: "/auth", host: "registry.example",
			want: "http://registry.example/auth"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{Cfg: &config.Config{TokenRealm: tc.configured}}
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
