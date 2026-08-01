package proxy

import "testing"

// Docker Hub's challenge is the shape that matters most here, and its
// parameters contain commas inside quoted values.
func TestParseChallenge(t *testing.T) {
	got := parseChallenge(
		`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull,push"`)
	if got["scheme"] != "bearer" {
		t.Errorf("scheme = %q", got["scheme"])
	}
	if got["realm"] != "https://auth.docker.io/token" {
		t.Errorf("realm = %q", got["realm"])
	}
	if got["service"] != "registry.docker.io" {
		t.Errorf("service = %q", got["service"])
	}
	// The comma inside the quoted scope must not split the parameter.
	if got["scope"] != "repository:library/alpine:pull,push" {
		t.Errorf("scope = %q, want the comma preserved", got["scope"])
	}
}

func TestParseChallengeBasic(t *testing.T) {
	got := parseChallenge(`Basic realm="container-registry"`)
	if got["scheme"] != "basic" || got["realm"] != "container-registry" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseChallengeEmpty(t *testing.T) {
	if got := parseChallenge(""); len(got) != 0 {
		t.Fatalf("an empty challenge yielded %+v", got)
	}
}
