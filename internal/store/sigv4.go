package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, implemented directly rather than by pulling in an
// SDK. The registry needs six S3 operations; the AWS SDK is a very large
// dependency to acquire for that, and the signing algorithm is a page of
// well-specified hashing.

const (
	sigAlgorithm  = "AWS4-HMAC-SHA256"
	sigTerminator = "aws4_request"
	// unsignedPayload lets a body be streamed without buffering it to compute a
	// hash first, which matters when the body is a multi-gigabyte layer.
	unsignedPayload = "UNSIGNED-PAYLOAD"
	emptyPayload    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// signV4 signs a request in place.
//
// payloadHash is the hex SHA-256 of the body, or UNSIGNED-PAYLOAD to stream it.
// Streaming is the normal case for blob uploads: the digest is verified by the
// registry anyway, and buffering a layer purely to satisfy a signature would
// defeat the point of streaming.
func signV4(req *http.Request, accessKey, secretKey, sessionToken, region, service, payloadHash string, now time.Time) {
	if payloadHash == "" {
		payloadHash = unsignedPayload
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	if req.Host != "" {
		req.Header.Set("Host", req.Host)
	} else {
		req.Header.Set("Host", req.URL.Host)
	}

	signedHeaders, canonicalHeaders := canonicalHeaderSet(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURIPath(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, sigTerminator}, "/")
	stringToSign := strings.Join([]string{
		sigAlgorithm,
		amzDate,
		scope,
		hashHex([]byte(canonicalRequest)),
	}, "\n")

	key := signingKey(secretKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigAlgorithm, accessKey, scope, signedHeaders, signature))
}

// canonicalHeaderSet renders the headers to sign, lowercased and sorted.
func canonicalHeaderSet(req *http.Request) (signed string, canonical string) {
	names := make([]string, 0, len(req.Header)+1)
	values := map[string]string{}
	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		// Only sign what the service will see unchanged. Authorization is the
		// output, and a proxy may rewrite the rest.
		switch lower {
		case "authorization", "user-agent", "content-length":
			continue
		}
		names = append(names, lower)
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = strings.Join(strings.Fields(v), " ")
		}
		values[lower] = strings.Join(trimmed, ",")
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return strings.Join(names, ";"), b.String()
}

// canonicalURIPath encodes the path segment by segment. The already-escaped
// path is used when present so a key containing a slash is not re-encoded.
func canonicalURIPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// canonicalQuery renders the query sorted, with both names and values encoded.
func canonicalQuery(u *url.URL) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vs := q[k]
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// uriEncode implements the encoding the signing specification requires, which
// differs from Go's url.QueryEscape: a space is %20 rather than +, and the
// unreserved set is left alone.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func signingKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte(sigTerminator))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
