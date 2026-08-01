package vuln

import "testing"

func TestParsePURL(t *testing.T) {
	cases := []struct {
		purl                          string
		typ, namespace, name, version string
	}{
		{"pkg:apk/alpine-3.16.2/openssl@1.1.1q-r0?arch=x86_64",
			"apk", "alpine-3.16.2", "openssl", "1.1.1q-r0"},
		{"pkg:deb/debian-12/curl@7.88.1-10+deb12u5?arch=amd64",
			"deb", "debian-12", "curl", "7.88.1-10+deb12u5"},
		{"pkg:rpm/rhel-8.10/openssl@1.1.1k-12.el8_9?arch=x86_64&epoch=1",
			"rpm", "rhel-8.10", "openssl", "1.1.1k-12.el8_9"},
		{"pkg:npm/lodash@4.17.21", "npm", "", "lodash", "4.17.21"},
		// A scoped npm package keeps its scope as the namespace.
		{"pkg:npm/@babel/core@7.24.0", "npm", "@babel", "core", "7.24.0"},
		{"pkg:pypi/requests@2.31.0", "pypi", "", "requests", "2.31.0"},
		{"pkg:golang/golang.org/x/crypto@v0.54.0",
			"golang", "golang.org/x", "crypto", "v0.54.0"},
	}
	for _, c := range cases {
		p, ok := parsePURL(c.purl)
		if !ok {
			t.Errorf("%s: rejected", c.purl)
			continue
		}
		if p.Type != c.typ || p.Namespace != c.namespace || p.Name != c.name || p.Version != c.version {
			t.Errorf("%s: got %+v", c.purl, p)
		}
	}
	for _, bad := range []string{"", "lodash@1.0", "pkg:", "pkg:npm", "pkg:npm/@scope"} {
		if _, ok := parsePURL(bad); ok {
			t.Errorf("parsePURL(%q) should have failed", bad)
		}
	}
}

// OSV indexes operating-system packages by ecosystem name and language packages
// by package URL. Getting this wrong is silent: the query succeeds and returns
// nothing, which reads as "no vulnerabilities" rather than "wrong question".
// The expected values were confirmed against the live API.
func TestQueryForUsesTheRightShape(t *testing.T) {
	cases := []struct {
		purl    string
		wantEco string // empty means the purl form is expected
		wantVer string
	}{
		{"pkg:apk/alpine-3.16.2/openssl@1.1.1q-r0?arch=x86_64", "Alpine:v3.16", "1.1.1q-r0"},
		{"pkg:apk/alpine-3.20.3/musl@1.2.5-r0", "Alpine:v3.20", "1.2.5-r0"},
		{"pkg:deb/debian-12/curl@7.88.1-10+deb12u5", "Debian:12", "7.88.1-10+deb12u5"},
		{"pkg:deb/ubuntu-22.04/openssl@3.0.2-0ubuntu1.10", "Ubuntu:22.04", "3.0.2-0ubuntu1.10"},
		{"pkg:rpm/rocky-9.3/openssl@3.0.7-24.el9", "Rocky Linux:9", "3.0.7-24.el9"},
		{"pkg:rpm/almalinux-9.3/openssl@3.0.7-24.el9", "AlmaLinux:9", "3.0.7-24.el9"},
		// Red Hat's feed is not split by release.
		{"pkg:rpm/rhel-8.10/openssl@1.1.1k-12.el8_9", "Red Hat", "1.1.1k-12.el8_9"},
		// Language ecosystems match on the package URL directly.
		{"pkg:npm/lodash@4.17.21", "", ""},
		{"pkg:pypi/requests@2.31.0", "", ""},
		{"pkg:golang/golang.org/x/crypto@v0.54.0", "", ""},
	}
	for _, c := range cases {
		q, ok := QueryFor(c.purl)
		if !ok {
			t.Errorf("%s: not queryable", c.purl)
			continue
		}
		if c.wantEco == "" {
			if q.PURL != c.purl || q.Ecosystem != "" {
				t.Errorf("%s: want a purl query, got %+v", c.purl, q)
			}
			continue
		}
		if q.PURL != "" {
			t.Errorf("%s: want an ecosystem query, got a purl one", c.purl)
			continue
		}
		if q.Ecosystem != c.wantEco || q.Version != c.wantVer {
			t.Errorf("%s: ecosystem/version = %q/%q, want %q/%q",
				c.purl, q.Ecosystem, q.Version, c.wantEco, c.wantVer)
		}
	}
}

// A component that cannot be matched must be reported as unqueryable rather
// than sent anyway and counted as clean when it comes back empty.
func TestQueryForRejectsUnmatchable(t *testing.T) {
	for _, purl := range []string{
		"",
		"not-a-purl",
		"pkg:apk/unknowndistro-1.0/thing@1.0", // no OSV ecosystem for it
		"pkg:apk/alpine-3.16.2/openssl",       // no version to compare against
		"pkg:oci/alpine@sha256:abc",           // the image itself, not a package
		"pkg:generic/something@1.0",
	} {
		if q, ok := QueryFor(purl); ok {
			t.Errorf("QueryFor(%q) returned %+v, want it rejected", purl, q)
		}
	}
}

func TestOSVEcosystemVersionGranularity(t *testing.T) {
	// Alpine tracks advisories per release branch, so the minor version matters
	// and a bare "Alpine" matches nothing at all.
	if got := osvEcosystem("apk", "alpine-3.16.2"); got != "Alpine:v3.16" {
		t.Errorf("alpine-3.16.2 -> %q", got)
	}
	if got := osvEcosystem("apk", "alpine"); got != "" {
		t.Errorf("alpine with no version -> %q, want it rejected", got)
	}
	// Debian and the RHEL rebuilds are tracked per major release.
	if got := osvEcosystem("deb", "debian-12"); got != "Debian:12" {
		t.Errorf("debian-12 -> %q", got)
	}
	if got := osvEcosystem("rpm", "rocky-9.3"); got != "Rocky Linux:9" {
		t.Errorf("rocky-9.3 -> %q", got)
	}
	// An unknown rpm distribution falls back to the Red Hat feed, which is the
	// closest thing to correct for a rebuild.
	if got := osvEcosystem("rpm", "somerebuild-9"); got != "Red Hat" {
		t.Errorf("unknown rpm distro -> %q", got)
	}
	// An unknown apk/deb distribution has no sensible fallback.
	if got := osvEcosystem("apk", "mystery-1.0"); got != "" {
		t.Errorf("unknown apk distro -> %q, want it rejected", got)
	}
}
