package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateURLRejectsInternalDestinations(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://localhost:8080/hook",
		"http://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://[::ffff:169.254.169.254]/meta",     // and its IPv6-mapped form
		"http://10.0.0.5/hook",
		"http://192.168.1.10/hook",
		"http://172.16.4.2/hook",
		"http://[::1]:9000/hook",
		"http://[fd00::1]/hook",
		"http://100.64.0.1/hook",
		"http://0.0.0.0/hook",
	} {
		var internal *ErrInternalDestination
		if err := ValidateURL(ctx, raw, false); !errors.As(err, &internal) {
			t.Errorf("ValidateURL(%q) = %v, want it refused as internal", raw, err)
		}
		// The escape hatch exists for receivers that really do live there.
		if err := ValidateURL(ctx, raw, true); err != nil {
			t.Errorf("ValidateURL(%q, allowInternal) = %v, want it allowed", raw, err)
		}
	}
}

func TestValidateURLAcceptsPublicAndRejectsNonsense(t *testing.T) {
	ctx := context.Background()
	if err := ValidateURL(ctx, "https://hooks.example.com/registry", false); err != nil {
		t.Errorf("a public https URL was refused: %v", err)
	}
	if err := ValidateURL(ctx, "https://93.184.216.34/hook", false); err != nil {
		t.Errorf("a public address was refused: %v", err)
	}
	for _, raw := range []string{"ftp://example.com/x", "file:///etc/passwd", "://", "https://"} {
		if err := ValidateURL(ctx, raw, false); err == nil {
			t.Errorf("ValidateURL(%q) was accepted", raw)
		}
	}
}

// The dial-time check is the one that matters: a name can resolve to a public
// address when the webhook is created and to a private one when it is
// delivered, and only the check at connect time sees the second answer.
func TestDeliveryRefusesInternalAddressAtDialTime(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a delivery reached a loopback receiver")
	}))
	defer receiver.Close()

	d := NewWithOptions(nil, nil, 8, time.Second, false)
	req, err := http.NewRequest(http.MethodPost, receiver.URL, strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := d.http.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("the delivery succeeded, want it refused before connecting")
	}
	var internal *ErrInternalDestination
	if !errors.As(err, &internal) {
		t.Fatalf("error = %v, want an internal-destination refusal", err)
	}
}

// A receiver must not be able to redirect a delivery somewhere else: it would
// pick the second destination itself, undoing the check on the first.
func TestDeliveryDoesNotFollowRedirects(t *testing.T) {
	var reached bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	d := NewWithOptions(nil, nil, 8, time.Second, true)
	req, _ := http.NewRequest(http.MethodPost, redirector.URL, strings.NewReader("{}"))
	resp, err := d.http.Do(req)
	if err != nil {
		t.Fatalf("delivery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the redirect returned unfollowed", resp.StatusCode)
	}
	if reached {
		t.Fatal("the delivery followed a redirect")
	}
}
