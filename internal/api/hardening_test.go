package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/container-registry/internal/config"
)

// The UI is served with a policy that confines every fetch to this origin and
// refuses framing, plugins and <base> rewriting outright.
func TestSecurityHeadersOnTheUI(t *testing.T) {
	h := newHarness(t)

	resp := h.do(http.MethodGet, "/", nil, anonymous())
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'", "object-src 'none'", "base-uri 'none'",
		"frame-ancestors 'none'", "form-action 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("Content-Security-Policy is missing %q: %s", want, csp)
		}
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// HSTS over plain HTTP is ignored by browsers and would be a lie on a registry
// deliberately run without TLS.
func TestHSTSOnlyOverASecureConnection(t *testing.T) {
	h := newHarness(t)
	h.server.Cfg.HSTSMaxAge = 365 * 24 * time.Hour

	resp := h.do(http.MethodGet, "/", nil, anonymous())
	resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("Strict-Transport-Security = %q over plain HTTP, want none", got)
	}

	// A trusted proxy saying the client's leg was HTTPS is enough.
	h.server.Cfg.TrustAllProxies = true
	resp = h.do(http.MethodGet, "/", nil, anonymous(), func(r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
	})
	resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
		t.Errorf("Strict-Transport-Security = %q behind a TLS-terminating proxy, want a max-age", got)
	}
}

// Anyone can send X-Forwarded-For. Believing it from an arbitrary caller lets
// that caller pick the address in the audit log and the bucket its failed
// logins are counted against.
func TestForwardedForIsOnlyBelievedFromATrustedProxy(t *testing.T) {
	tests := []struct {
		name     string
		trust    string
		trustAll bool
		xff      string
		remote   string
		want     string
	}{
		{name: "untrusted peer is taken at face value",
			xff: "203.0.113.9", remote: "198.51.100.4:5000", want: "198.51.100.4"},
		{name: "trusted proxy is believed",
			trust: "198.51.100.4", xff: "203.0.113.9",
			remote: "198.51.100.4:5000", want: "203.0.113.9"},
		{name: "a CIDR block covers the proxy",
			trust: "198.51.100.0/24", xff: "203.0.113.9",
			remote: "198.51.100.4:5000", want: "203.0.113.9"},
		{name: "client-supplied hops left of the trusted chain are ignored",
			trust: "198.51.100.0/24", xff: "1.1.1.1, 203.0.113.9, 198.51.100.7",
			remote: "198.51.100.4:5000", want: "203.0.113.9"},
		{name: "no header falls back to the peer",
			trust: "198.51.100.0/24", remote: "198.51.100.4:5000", want: "198.51.100.4"},
		{name: "a wildcard trusts any peer",
			trustAll: true, xff: "203.0.113.9",
			remote: "198.51.100.4:5000", want: "203.0.113.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{TrustAllProxies: tc.trustAll}
			if tc.trust != "" {
				parsed, all, err := config.ParseTrustedProxies(tc.trust)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.trust, err)
				}
				cfg.TrustedProxies, cfg.TrustAllProxies = parsed, all
			}
			s := &Server{Cfg: cfg}
			r := httptest.NewRequest(http.MethodGet, "/v2/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := s.remoteIP(r); got != tc.want {
				t.Errorf("remoteIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// A webhook naming an internal address is refused where it is written, so the
// mistake surfaces immediately rather than as a delivery failure later.
func TestWebhookCreateRefusesInternalURL(t *testing.T) {
	h := newHarness(t)

	resp := h.do(http.MethodPost, "/api/webhooks",
		[]byte(`{"name":"metadata","url":"http://169.254.169.254/latest/meta-data/"}`))
	body := h.expectStatus(resp, http.StatusBadRequest, "a webhook pointed at cloud metadata")
	if !strings.Contains(string(body), "REGISTRY_WEBHOOK_ALLOW_INTERNAL") {
		t.Errorf("the refusal should name the setting that permits it: %s", body)
	}

	// The escape hatch works for a receiver that really does live there.
	h.server.Cfg.WebhookAllowInternal = true
	resp = h.do(http.MethodPost, "/api/webhooks",
		[]byte(`{"name":"internal","url":"http://10.0.0.5/hook"}`))
	h.expectStatus(resp, http.StatusCreated, "an internal webhook with the setting on")
}
