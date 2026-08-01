package vuln

import "testing"

// Cases taken from rpm's own rpmvercmp test suite, which is the definition of
// correct here.
func TestCompareRPMVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1a", 0},
		{"2.0.1a", "2.0.1", 1},
		{"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p1", 0},
		{"5.5p1", "5.5p2", -1},
		{"5.5p10", "5.5p10", 0},
		{"5.5p1", "5.5p10", -1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10", 0},
		{"xyz10", "xyz10.1", -1},
		{"xyz.4", "xyz.4", 0},
		{"xyz.4", "8", -1},
		{"xyz.4", "2", -1},
		{"1.0001", "1.1", 0}, // leading zeros are stripped before comparing
		{"1.0", "1.0a", -1},
		{"a", "a", 0},
		{"a+", "a+", 0},
		{"a+", "a_", 0}, // separators are not significant
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1", "1.0~rc1", 0},
		{"1.0", "1.0~rc1", 1},
		{"1.0^", "1.0", 1},
		{"1.0^", "1.0^", 0},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0^git2", -1},
		{"", "", 0},
		{"", "1", -1},
		{"1", "", 1},
	}
	for _, c := range cases {
		if got := CompareRPMVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareRPMVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareEVR(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// A higher epoch wins outright, however old the version looks.
		{"1:1.0-1", "2.0-1", 1},
		{"0:1.0-1", "1.0-1", 0},
		{"1.1.1k-12.el8_9", "1.1.1k-12.el8_9", 0},
		{"1.1.1k-12.el8_9", "1.1.1k-13.el8_9", -1},
		{"1.1.1k-13.el8_9", "1.1.1k-12.el8_9", 1},
		// The case that started this: a RHEL 8 package against a RHEL 9 fix.
		{"7.61.1-34.el8_10.11", "0:7.76.1-14.el9_0.5", -1},
		{"3.0.7-24.el9", "3.0.7-24.el9", 0},
	}
	for _, c := range cases {
		if got := CompareEVR(c.a, c.b); got != c.want {
			t.Errorf("CompareEVR(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseEVR(t *testing.T) {
	cases := map[string]evr{
		"1:1.1.1k-12.el8_9":   {1, "1.1.1k", "12.el8_9"},
		"1.1.1k-12.el8_9":     {0, "1.1.1k", "12.el8_9"},
		"1.1.1k":              {0, "1.1.1k", ""},
		"0:7.76.1-14.el9_0.5": {0, "7.76.1", "14.el9_0.5"},
	}
	for in, want := range cases {
		if got := parseEVR(in); got != want {
			t.Errorf("parseEVR(%q) = %+v, want %+v", in, got, want)
		}
	}
}

// The epoch is carried in a package URL qualifier rather than in the version
// string. Dropping it makes a patched package look vulnerable: vim-minimal in
// RHEL 8 has epoch 2, so comparing its version as epoch 0 against a fix of
// "2:..." always says "older", however new the release is.
func TestEVRFromPURLKeepsEpoch(t *testing.T) {
	const purl = "pkg:rpm/rhel-8.10/vim-minimal@8.0.1763-27.el8_10?arch=x86_64&epoch=2"
	got := EVRFromPURL(purl)
	if got != "2:8.0.1763-27.el8_10" {
		t.Fatalf("EVRFromPURL = %q, want the epoch included", got)
	}
	// With the epoch, the installed release 27 correctly beats the fix at 22.
	if CompareEVR(got, "2:8.0.1763-22.el8_10.3") <= 0 {
		t.Fatal("installed release 27 should compare newer than the fix at release 22")
	}
	// Without it, the same comparison wrongly reports the package as older.
	if CompareEVR("8.0.1763-27.el8_10", "2:8.0.1763-22.el8_10.3") >= 0 {
		t.Fatal("this test no longer demonstrates the bug it guards against")
	}
	// A package with no epoch qualifier is unchanged.
	if got := EVRFromPURL("pkg:rpm/rocky-9.3/openssl@3.0.7-24.el9?arch=x86_64"); got != "3.0.7-24.el9" {
		t.Fatalf("EVRFromPURL without epoch = %q", got)
	}
}
