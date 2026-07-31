package sbom

import (
	"testing"
)

// ---------------------------------------------------------------- npm

func TestIsNPMManifest(t *testing.T) {
	cases := map[string]bool{
		"app/node_modules/lodash/package.json":              true,
		"usr/src/app/node_modules/@babel/core/package.json": true,
		"node_modules/a/node_modules/b/package.json":        true,
		"usr/lib/node_modules/npm/package.json":             true,
		// The project's own manifest describes intent, not what is installed.
		"app/package.json": false,
		// node_modules itself is not a package.
		"app/node_modules/package.json": false,
		// npm bookkeeping directories.
		"app/node_modules/.package-lock.json": false,
		"app/node_modules/.bin/package.json":  false,
		// A scoped path must still sit under node_modules.
		"app/@babel/core/package.json": false,
		// Not a manifest at all.
		"app/node_modules/lodash/index.js":                            false,
		"app/node_modules/lodash/test/fixtures/package.json.template": false,
	}
	for path, want := range cases {
		if got := isNPMManifest(path); got != want {
			t.Errorf("isNPMManifest(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestParseNPM(t *testing.T) {
	p := parseNPM("app/node_modules/lodash/package.json",
		[]byte(`{"name":"lodash","version":"4.17.21","license":"MIT"}`))
	if len(p) != 1 {
		t.Fatalf("parsed %d packages, want 1", len(p))
	}
	if p[0].Name != "lodash" || p[0].Version != "4.17.21" || p[0].License != "MIT" {
		t.Fatalf("package = %+v", p[0])
	}
	if want := "pkg:npm/lodash@4.17.21"; p[0].purl("") != want {
		t.Errorf("purl = %q, want %q", p[0].purl(""), want)
	}

	// A scoped name keeps its slash in the package URL.
	scoped := parseNPM("app/node_modules/@babel/core/package.json",
		[]byte(`{"name":"@babel/core","version":"7.24.0"}`))
	if len(scoped) != 1 || scoped[0].purl("") != "pkg:npm/@babel/core@7.24.0" {
		t.Fatalf("scoped package = %+v", scoped)
	}
}

// The license field has taken several shapes over npm's history.
func TestParseNPMLicenseShapes(t *testing.T) {
	cases := map[string]string{
		`{"name":"a","version":"1","license":"MIT"}`:                            "MIT",
		`{"name":"a","version":"1","license":{"type":"Apache-2.0"}}`:            "Apache-2.0",
		`{"name":"a","version":"1","licenses":[{"type":"MIT"},{"type":"GPL"}]}`: "MIT, GPL",
		`{"name":"a","version":"1"}`:                                            "",
	}
	for body, want := range cases {
		got := parseNPM("node_modules/a/package.json", []byte(body))
		if len(got) != 1 {
			t.Fatalf("%s: parsed %d packages", body, len(got))
		}
		if got[0].License != want {
			t.Errorf("%s: license = %q, want %q", body, got[0].License, want)
		}
	}
}

func TestParseNPMRejectsIncomplete(t *testing.T) {
	// Without both a name and a version the entry cannot be matched against an
	// advisory, so it is worse than useless in a bill of materials.
	for _, body := range []string{
		`{"name":"no-version"}`,
		`{"version":"1.0.0"}`,
		`{}`,
		`not json at all`,
	} {
		if got := parseNPM("node_modules/a/package.json", []byte(body)); len(got) != 0 {
			t.Errorf("%s produced %+v, want nothing", body, got)
		}
	}
}

// ---------------------------------------------------------------- python

func TestIsPythonMetadata(t *testing.T) {
	cases := map[string]bool{
		"usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA":   true,
		"usr/local/lib/python3.9/site-packages/six-1.16.0.egg-info/PKG-INFO":    true,
		"app/.venv/lib/python3.12/site-packages/flask-3.0.0.dist-info/METADATA": true,
		"usr/lib/python3.11/site-packages/requests/METADATA":                    false,
		"usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/RECORD":     false,
		"some/METADATA": false,
	}
	for path, want := range cases {
		if got := isPythonMetadata(path); got != want {
			t.Errorf("isPythonMetadata(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestParsePython(t *testing.T) {
	metadata := `Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
License: Apache 2.0
Classifier: Programming Language :: Python :: 3
Requires-Dist: urllib3

This is the long description, which must not be parsed as headers.
Name: not-a-real-field
`
	got := parsePython("usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA",
		[]byte(metadata))
	if len(got) != 1 {
		t.Fatalf("parsed %d packages, want 1", len(got))
	}
	p := got[0]
	if p.Name != "requests" || p.Version != "2.31.0" {
		t.Fatalf("package = %+v", p)
	}
	if p.License != "Apache 2.0" {
		t.Errorf("license = %q", p.License)
	}
	if want := "pkg:pypi/requests@2.31.0"; p.purl("") != want {
		t.Errorf("purl = %q, want %q", p.purl(""), want)
	}
}

// Advisory databases key on the PEP 503 normalised name.
func TestPythonNameNormalisation(t *testing.T) {
	cases := map[string]string{
		"Requests":           "requests",
		"zope.interface":     "zope-interface",
		"ruamel_yaml":        "ruamel-yaml",
		"Flask-SQLAlchemy":   "flask-sqlalchemy",
		"backports.zoneinfo": "backports-zoneinfo",
		"a__b":               "a-b",
	}
	for in, want := range cases {
		if got := normalisePythonName(in); got != want {
			t.Errorf("normalisePythonName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Older packages carry their license only as a trove classifier.
func TestParsePythonLicenseFromClassifier(t *testing.T) {
	got := parsePython("x.dist-info/METADATA", []byte(
		"Name: six\nVersion: 1.16.0\nClassifier: License :: OSI Approved :: MIT License\n"))
	if len(got) != 1 {
		t.Fatalf("parsed %d packages", len(got))
	}
	if got[0].License != "MIT License" {
		t.Errorf("license = %q, want it taken from the classifier", got[0].License)
	}

	// PEP 639's License-Expression wins over the legacy free-text field.
	got = parsePython("x.dist-info/METADATA", []byte(
		"Name: attrs\nVersion: 23.2.0\nLicense: see LICENSE file\nLicense-Expression: MIT\n"))
	if len(got) != 1 || got[0].License != "MIT" {
		t.Fatalf("package = %+v, want the License-Expression value", got)
	}
}

func TestParsePythonRejectsIncomplete(t *testing.T) {
	for _, body := range []string{
		"Name: no-version\n",
		"Version: 1.0\n",
		"",
	} {
		if got := parsePython("x.dist-info/METADATA", []byte(body)); len(got) != 0 {
			t.Errorf("%q produced %+v, want nothing", body, got)
		}
	}
}

// ---------------------------------------------------------------- end to end

func TestScanFindsLanguagePackages(t *testing.T) {
	layer := tarLayer(t, map[string]string{
		"etc/os-release":                                                      "ID=debian\nVERSION_ID=12\n",
		"app/node_modules/lodash/package.json":                                `{"name":"lodash","version":"4.17.21","license":"MIT"}`,
		"app/node_modules/@babel/core/package.json":                           `{"name":"@babel/core","version":"7.24.0"}`,
		"usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA": "Name: requests\nVersion: 2.31.0\n",
		"app/package.json":                                                    `{"name":"my-app","version":"0.0.1"}`, // the project itself: excluded
	}, nil)

	res, err := Scan([]LayerSource{layerFrom(layer)}, DefaultLimits())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	found := map[string]pkg{}
	for _, p := range res.Packages {
		found[p.Name] = p
	}
	for _, want := range []string{"lodash", "@babel/core", "requests"} {
		if _, ok := found[want]; !ok {
			t.Errorf("%s was not found; got %+v", want, res.Packages)
		}
	}
	if _, ok := found["my-app"]; ok {
		t.Error("the project's own package.json was reported as an installed package")
	}
	if found["lodash"].Ecosystem != "npm" || found["requests"].Ecosystem != "pypi" {
		t.Errorf("ecosystems = %q / %q", found["lodash"].Ecosystem, found["requests"].Ecosystem)
	}
}

// Reaching the language-package cap must be recorded, not hidden.
func TestScanReportsTruncatedManifests(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		name := "p" + string(rune('a'+i))
		files["app/node_modules/"+name+"/package.json"] =
			`{"name":"` + name + `","version":"1.0.0"}`
	}
	limits := DefaultLimits()
	limits.MaxManifests = 5

	res, err := Scan([]LayerSource{layerFrom(tarLayer(t, files, nil))}, limits)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.ManifestsTruncated {
		t.Fatal("hitting the manifest cap must be reported")
	}
	if len(res.Packages) != 5 {
		t.Fatalf("kept %d packages, want the cap of 5", len(res.Packages))
	}
}

// A dependency removed in a later layer must not appear in the bill of materials.
func TestScanWhiteoutRemovesLanguagePackages(t *testing.T) {
	base := tarLayer(t, map[string]string{
		"app/node_modules/lodash/package.json":   `{"name":"lodash","version":"4.17.21"}`,
		"app/node_modules/left-pad/package.json": `{"name":"left-pad","version":"1.3.0"}`,
	}, nil)
	// Deleting the whole package directory whites out the manifest beneath it.
	removed := tarLayer(t, map[string]string{"app/node_modules/.wh.left-pad": ""}, nil)

	res, err := Scan([]LayerSource{layerFrom(base), layerFrom(removed)}, DefaultLimits())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "lodash" {
		t.Fatalf("packages = %+v, want only lodash to survive", res.Packages)
	}
}
