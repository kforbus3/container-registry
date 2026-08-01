// Package vuln matches the package inventory of a pushed image against a
// vulnerability database, turning the bill of materials from a description of
// what is installed into a statement about what is wrong with it.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultEndpoint is the public OSV.dev API. It needs no credentials and
// covers every ecosystem the SBOM scanner detects: apk, deb, rpm, npm, PyPI
// and Go. Point Endpoint at a mirror to run without egress.
const DefaultEndpoint = "https://api.osv.dev"

// batchLimit is the number of queries OSV accepts in one request.
const batchLimit = 1000

// Client talks to an OSV-compatible API.
type Client struct {
	Endpoint string
	HTTP     *http.Client
}

func NewClient(endpoint string, timeout time.Duration) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		Endpoint: strings.TrimRight(endpoint, "/"),
		HTTP:     &http.Client{Timeout: timeout},
	}
}

// ---------------------------------------------------------------- wire types

// batchQuery carries either a package URL or an ecosystem-qualified name,
// because OSV indexes language packages by the former and operating-system
// packages by the latter.
type batchQuery struct {
	Package struct {
		PURL      string `json:"purl,omitempty"`
		Name      string `json:"name,omitempty"`
		Ecosystem string `json:"ecosystem,omitempty"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

// Advisory is the detail OSV holds about one vulnerability.
type Advisory struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Modified string   `json:"modified"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Rating derives a comparable severity and score for the advisory.
func (a *Advisory) Rating() (string, float64) {
	vectors := make([]string, 0, len(a.Severity))
	for _, s := range a.Severity {
		vectors = append(vectors, s.Score)
	}
	return severityFromAdvisory(vectors, a.DatabaseSpecific.Severity)
}

// FixedVersion reports the earliest version the advisory says the problem is
// fixed in, which is the single most actionable field for whoever has to
// remediate it. An advisory with no fix recorded returns "".
func (a *Advisory) FixedVersion() string {
	var fixes []string
	for _, aff := range a.Affected {
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixes = append(fixes, e.Fixed)
				}
			}
		}
	}
	if len(fixes) == 0 {
		return ""
	}
	sort.Strings(fixes)
	return fixes[0]
}

// ---------------------------------------------------------------- requests

// QueryBatch asks which advisories affect each package. The result is
// index-aligned with the input, so a package with no advisories yields an
// empty slice rather than being omitted.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([][]string, error) {
	out := make([][]string, len(queries))
	for start := 0; start < len(queries); start += batchLimit {
		end := min(start+batchLimit, len(queries))
		chunk := queries[start:end]

		req := batchRequest{Queries: make([]batchQuery, len(chunk))}
		for i, q := range chunk {
			if q.PURL != "" {
				req.Queries[i].Package.PURL = q.PURL
			} else {
				req.Queries[i].Package.Name = q.Name
				req.Queries[i].Package.Ecosystem = q.Ecosystem
				req.Queries[i].Version = q.Version
			}
		}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		var resp batchResponse
		if err := c.post(ctx, "/v1/querybatch", body, &resp); err != nil {
			return nil, err
		}
		// A short result array would silently misalign findings with packages,
		// so treat it as a protocol error rather than guessing.
		if len(resp.Results) != len(chunk) {
			return nil, fmt.Errorf("querybatch returned %d results for %d queries",
				len(resp.Results), len(chunk))
		}
		for i, r := range resp.Results {
			ids := make([]string, 0, len(r.Vulns))
			for _, v := range r.Vulns {
				ids = append(ids, v.ID)
			}
			out[start+i] = ids
		}
	}
	return out, nil
}

// Advisory fetches the full record for one vulnerability identifier.
// Advisory fetches one advisory, returning both the parsed record and the
// document it was parsed from. The raw form is what gets cached: re-encoding
// the struct would silently drop any field this client does not model, and the
// affected ranges it holds are what later scans re-derive their answers from.
func (c *Client) Advisory(ctx context.Context, id string) (*Advisory, []byte, error) {
	var a Advisory
	raw, err := c.get(ctx, "/v1/vulns/"+id, &a)
	if err != nil {
		return nil, nil, err
	}
	return &a, raw, nil
}

// ParseAdvisory decodes a cached advisory document.
func ParseAdvisory(raw []byte) (*Advisory, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var a Advisory
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, false
	}
	return &a, true
}

func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = c.do(req, out)
	return err
}

func (c *Client) get(ctx context.Context, path string, out any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req, out)
}

// do sends the request and returns the response body alongside the decoded
// value, so a caller that wants to keep the original document can.
func (c *Client) do(req *http.Request, out any) ([]byte, error) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "container-registry/vuln")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Bound the read: this is a third-party service and a runaway response
	// should not become a memory problem.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 200 {
			snippet = snippet[:200] + "…"
		}
		return nil, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status, snippet)
	}
	return body, json.Unmarshal(body, out)
}
