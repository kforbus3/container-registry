package sbom

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func buildJar(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseJavaArchive(t *testing.T) {
	// Maven coordinates are preferred: they are the only place the group id is
	// recorded exactly, and the group is what a purl needs.
	jar := buildJar(t, map[string]string{
		"META-INF/maven/org.slf4j/slf4j-api/pom.properties": "groupId=org.slf4j\nartifactId=slf4j-api\nversion=2.0.13\n",
		"META-INF/MANIFEST.MF":                              "Implementation-Title: something-else\nImplementation-Version: 9.9.9\n",
	})
	got := parseJavaArchive("opt/app/slf4j-api-2.0.13.jar", jar)
	if len(got) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(got), got)
	}
	if got[0].Name != "org.slf4j:slf4j-api" || got[0].Version != "2.0.13" {
		t.Errorf("got %s@%s, want org.slf4j:slf4j-api@2.0.13", got[0].Name, got[0].Version)
	}
	if p := (got[0]).purl(""); p != "pkg:maven/org.slf4j/slf4j-api@2.0.13" {
		t.Errorf("purl = %s", p)
	}

	// Without Maven metadata the manifest is used.
	jar = buildJar(t, map[string]string{
		"META-INF/MANIFEST.MF": "Implementation-Title: guava\nImplementation-Version: 33.2.0-jre\n",
	})
	got = parseJavaArchive("opt/guava.jar", jar)
	if len(got) != 1 || got[0].Name != "guava" || got[0].Version != "33.2.0-jre" {
		t.Errorf("manifest fallback gave %+v", got)
	}

	// And with neither, the file name.
	got = parseJavaArchive("opt/commons-io-2.16.1.jar", buildJar(t, map[string]string{"a.class": "x"}))
	if len(got) != 1 || got[0].Name != "commons-io" || got[0].Version != "2.16.1" {
		t.Errorf("file-name fallback gave %+v", got)
	}

	// Something that is not a zip must not produce a phantom component.
	if got := parseJavaArchive("opt/broken.jar", []byte("not a zip")); got != nil {
		t.Errorf("a non-archive produced %+v", got)
	}
}

func TestIsGemspecAndParse(t *testing.T) {
	for _, p := range []string{
		"usr/local/lib/ruby/gems/3.3.0/specifications/rake-13.2.1.gemspec",
		"usr/local/lib/ruby/gems/3.3.0/specifications/default/json-2.7.2.gemspec",
	} {
		if !isGemspec(p) {
			t.Errorf("%s should be recognised as a gemspec", p)
		}
	}
	if isGemspec("app/mygem.gemspec") {
		t.Error("a gemspec outside specifications/ is a project file, not an installed gem")
	}

	spec := `Gem::Specification.new do |s|
  s.name = "rake".freeze
  s.version = "13.2.1".freeze
  s.licenses = ["MIT".freeze]
end`
	got := parseGemspec("specifications/rake-13.2.1.gemspec", []byte(spec))
	if len(got) != 1 || got[0].Name != "rake" || got[0].Version != "13.2.1" {
		t.Fatalf("got %+v", got)
	}
	if got[0].License != "MIT" {
		t.Errorf("license = %q", got[0].License)
	}
	if p := got[0].purl(""); p != "pkg:gem/rake@13.2.1" {
		t.Errorf("purl = %s", p)
	}

	// A gemspec whose assignments are computed still yields the name and
	// version, because RubyGems writes them into the file name too.
	got = parseGemspec("specifications/nokogiri-1.16.5.gemspec", []byte("computed at load time"))
	if len(got) != 1 || got[0].Name != "nokogiri" || got[0].Version != "1.16.5" {
		t.Errorf("file-name fallback gave %+v", got)
	}
}

func TestParseDotNetDeps(t *testing.T) {
	deps := `{"libraries":{
	  "Newtonsoft.Json/13.0.3": {"type":"package"},
	  "MyApp/1.0.0": {"type":"project"},
	  "Serilog/3.1.1": {"type":"package"}}}`
	got := parseDotNetDeps("app/MyApp.deps.json", []byte(deps))
	names := map[string]string{}
	for _, p := range got {
		names[p.Name] = p.Version
	}
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2 (the project itself is not a dependency): %v", len(got), names)
	}
	if names["Newtonsoft.Json"] != "13.0.3" || names["Serilog"] != "3.1.1" {
		t.Errorf("got %v", names)
	}
	if _, ok := names["MyApp"]; ok {
		t.Error("the application's own project was reported as a package")
	}
}

func TestParseComposerInstalled(t *testing.T) {
	// Composer 2 wraps the list in an object.
	v2 := `{"packages":[{"name":"monolog/monolog","version":"v3.6.0","license":["MIT"]}]}`
	got := parseComposerInstalled("app/vendor/composer/installed.json", []byte(v2))
	if len(got) != 1 || got[0].Name != "monolog/monolog" || got[0].Version != "3.6.0" {
		t.Fatalf("composer 2 gave %+v", got)
	}
	if p := got[0].purl(""); p != "pkg:composer/monolog/monolog@3.6.0" {
		t.Errorf("purl = %s", p)
	}
	// Composer 1 used a bare array.
	v1 := `[{"name":"psr/log","version":"1.1.4"}]`
	got = parseComposerInstalled("app/vendor/composer/installed.json", []byte(v1))
	if len(got) != 1 || got[0].Name != "psr/log" {
		t.Errorf("composer 1 gave %+v", got)
	}
}

func TestRuntimeProbe(t *testing.T) {
	// The path establishes which runtime it is, so a loose version pattern
	// cannot attach a version to the wrong thing.
	probe, ok := runtimeProbeFor("usr/local/lib/libpython3.11.so.1.0")
	if !ok || probe.name != "python" {
		t.Fatalf("libpython not recognised: %+v %v", probe, ok)
	}
	body := strings.Repeat("padding", 100) + "3.11.15" + strings.Repeat("x", 50)
	p, found := scanRuntime(probe, "usr/local/lib/libpython3.11.so.1.0", strings.NewReader(body), 1<<20)
	if !found || p.Version != "3.11.15" {
		t.Errorf("python version = %+v found=%v", p, found)
	}

	probe, ok = runtimeProbeFor("usr/local/bin/node")
	if !ok || probe.name != "node" {
		t.Fatalf("node not recognised")
	}
	p, found = scanRuntime(probe, "usr/local/bin/node", strings.NewReader("junk node.js/v20.20.2 junk"), 1<<20)
	if !found || p.Version != "20.20.2" {
		t.Errorf("node version = %+v found=%v", p, found)
	}

	if _, ok := runtimeProbeFor("usr/bin/ls"); ok {
		t.Error("an ordinary binary was treated as a runtime")
	}
}

// TestScanRuntimeAcrossChunkBoundary covers the reason the scan carries a tail
// between reads: a version string split across two reads would otherwise be
// missed, and which side of a 1 MiB boundary it lands on is arbitrary.
func TestScanRuntimeAcrossChunkBoundary(t *testing.T) {
	probe, _ := runtimeProbeFor("usr/local/bin/node")
	marker := "node.js/v18.19.1"
	// Place the marker so it straddles the internal 1 MiB read window.
	pad := strings.Repeat("a", (1<<20)-len(marker)/2)
	p, found := scanRuntime(probe, "usr/local/bin/node",
		strings.NewReader(pad+marker+"tail"), 4<<20)
	if !found || p.Version != "18.19.1" {
		t.Errorf("marker spanning a read boundary was missed: %+v found=%v", p, found)
	}
}

// TestManifestContinuationLines covers the jar manifest wrapping rule. Values
// wrap at 72 bytes onto a line beginning with a single space, and reading them
// line by line silently truncates anything longer -- which is how a component
// name once arrived cut off mid-word.
func TestManifestContinuationLines(t *testing.T) {
	body := "Manifest-Version: 1.0\n" +
		"Bundle-SymbolicName: org.example.some.very.long.bundle.identifier.th\n" +
		" at.wraps\n" +
		"Bundle-Version: 4.5.6\n"
	fields := parseManifestFields([]byte(body))
	want := "org.example.some.very.long.bundle.identifier.that.wraps"
	if fields["Bundle-SymbolicName"] != want {
		t.Errorf("got %q, want %q", fields["Bundle-SymbolicName"], want)
	}

	jar := buildJar(t, map[string]string{"META-INF/MANIFEST.MF": body})
	got := parseJavaArchive("opt/thing.jar", jar)
	if len(got) != 1 || got[0].Name != want || got[0].Version != "4.5.6" {
		t.Errorf("parse gave %+v", got)
	}
}

// TestManifestProseIsNotAPackageName is the regression test for a malformed
// purl. ASM sets Implementation-Title to a sentence; a name with spaces and
// commas cannot appear in a package URL and would match no advisory.
func TestManifestProseIsNotAPackageName(t *testing.T) {
	body := "Implementation-Title: ASM, a very small and fast Java bytecode manipul\n" +
		" ation framework\n" +
		"Implementation-Version: 9.9.1\n"
	jar := buildJar(t, map[string]string{"META-INF/MANIFEST.MF": body})

	// No usable identifier and no version in the file name: report nothing
	// rather than a name that cannot be expressed as a purl.
	if got := parseJavaArchive("opt/lib/asm.jar", jar); len(got) != 0 {
		t.Errorf("prose was accepted as a package name: %+v", got)
	}

	// The same archive named properly falls back to the file name.
	got := parseJavaArchive("opt/lib/asm-9.9.1.jar", jar)
	if len(got) != 1 || got[0].Name != "asm" || got[0].Version != "9.9.1" {
		t.Errorf("file-name fallback gave %+v", got)
	}

	// An identifier-shaped title is still accepted.
	body = "Implementation-Title: commons-lang3\nImplementation-Version: 3.14.0\n"
	got = parseJavaArchive("opt/lib/x.jar", buildJar(t, map[string]string{"META-INF/MANIFEST.MF": body}))
	if len(got) != 1 || got[0].Name != "commons-lang3" {
		t.Errorf("identifier-shaped title rejected: %+v", got)
	}
}

func TestIsIdentifierLike(t *testing.T) {
	for _, ok := range []string{"org.slf4j", "commons-io", "gson", "org.example.Bundle"} {
		if !isIdentifierLike(ok) {
			t.Errorf("%q should be usable as a package name", ok)
		}
	}
	for _, bad := range []string{"", "Java Runtime Environment", "ASM, a framework", "a (b)"} {
		if isIdentifierLike(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
