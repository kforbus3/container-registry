package store

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The AWS Signature Version 4 test suite publishes worked examples with known
// intermediate values. Getting any step wrong yields a signature that is
// rejected with an opaque 403, so the steps are checked individually.

func TestSigningKeyMatchesPublishedExample(t *testing.T) {
	// From the specification's worked example.
	key := signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20150830", "us-east-1", "iam")
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got := hex.EncodeToString(key); got != want {
		t.Fatalf("signing key = %s, want %s", got, want)
	}
}

func TestCanonicalQuerySortsAndEncodes(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet,
		"https://example.com/?list-type=2&prefix=blobs/sha256/&max-keys=10", nil)
	got := canonicalQuery(req.URL)
	want := "list-type=2&max-keys=10&prefix=blobs%2Fsha256%2F"
	if got != want {
		t.Fatalf("canonical query = %q, want %q", got, want)
	}
}

// The signing encoder is not url.QueryEscape: a space is %20, not '+', and the
// unreserved set is left alone.
func TestURIEncodeFollowsTheSigningRules(t *testing.T) {
	cases := map[string]string{
		"a b":       "a%20b",
		"a+b":       "a%2Bb",
		"a/b":       "a%2Fb",
		"a-_.~b":    "a-_.~b",
		"sha256:ab": "sha256%3Aab",
	}
	for in, want := range cases {
		if got := uriEncode(in, true); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
	}
	// A path keeps its slashes when they are structural.
	if got := uriEncode("blobs/sha256/ab", false); got != "blobs/sha256/ab" {
		t.Errorf("path encoding = %q", got)
	}
}

func TestCanonicalHeadersAreSortedAndTrimmed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPut, "https://example.com/key", nil)
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Host", "example.com")
	// Excess internal whitespace is collapsed by the signing rules.
	req.Header.Set("X-Amz-Meta-Test", "a    b")
	// These must not be signed: Authorization is the output, and the others may
	// legitimately be rewritten in transit.
	req.Header.Set("Authorization", "should not appear")
	req.Header.Set("User-Agent", "should not appear")

	signed, canonical := canonicalHeaderSet(req)
	if strings.Contains(signed, "authorization") || strings.Contains(signed, "user-agent") {
		t.Fatalf("signed headers must exclude authorization and user-agent: %s", signed)
	}
	if !strings.Contains(canonical, "x-amz-meta-test:a b\n") {
		t.Fatalf("whitespace was not collapsed: %q", canonical)
	}
	// Sorted, colon-separated, lowercase.
	if signed != "content-type;host;x-amz-date;x-amz-meta-test" {
		t.Fatalf("signed headers = %q", signed)
	}
}

// A full signature is deterministic for a fixed time, so a regression in any
// step shows up here.
func TestSignV4IsDeterministic(t *testing.T) {
	when := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	sign := func() string {
		req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.us-east-1.amazonaws.com/blobs/sha256/ab/abcd", nil)
		signV4(req, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
			"", "us-east-1", "s3", emptyPayload, when)
		return req.Header.Get("Authorization")
	}
	first, second := sign(), sign()
	if first != second {
		t.Fatal("signing the same request twice produced different signatures")
	}
	for _, want := range []string{sigAlgorithm, "Credential=AKIDEXAMPLE/20260801/us-east-1/s3/aws4_request",
		"SignedHeaders=", "Signature="} {
		if !strings.Contains(first, want) {
			t.Errorf("Authorization header missing %q: %s", want, first)
		}
	}
	// A different secret must produce a different signature.
	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.us-east-1.amazonaws.com/blobs/sha256/ab/abcd", nil)
	signV4(req, "AKIDEXAMPLE", "a-different-secret", "", "us-east-1", "s3", emptyPayload, when)
	if req.Header.Get("Authorization") == first {
		t.Fatal("the signature does not depend on the secret key")
	}
}

// A session token has to be signed, or temporary credentials silently fail.
func TestSessionTokenIsSigned(t *testing.T) {
	when := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	req, _ := http.NewRequest(http.MethodGet, "https://bucket.s3.amazonaws.com/x", nil)
	signV4(req, "AKID", "secret", "session-token-value", "us-east-1", "s3", emptyPayload, when)

	if req.Header.Get("X-Amz-Security-Token") != "session-token-value" {
		t.Fatal("the session token was not sent")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Fatal("the session token must be part of the signed headers")
	}
}
