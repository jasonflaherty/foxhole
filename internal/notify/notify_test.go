package notify_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/notify"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestTeamsNotify(t *testing.T) {
	var gotURL string
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	n := notify.TeamsNotifier{Webhook: "https://example.com/hook", Client: client}
	err := n.Notify(context.Background(), &scan.Result{Target: "/app", Findings: []scan.Finding{{
		Kind: scan.KindVuln, VulnID: "CVE-1", Summary: "x", Severity: "high", Source: "nvd",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if gotURL != "https://example.com/hook" {
		t.Fatalf("url = %q", gotURL)
	}
}

func TestSelect(t *testing.T) {
	cfg := notify.Config{TeamsWebhook: "x", GitHubToken: "t", GitHubRepo: "o/r", SMTPHost: "h", EmailFrom: "a", EmailTo: "b"}
	ns := notify.Select(cfg, true, true, true)
	if len(ns) != 3 {
		t.Fatalf("len = %d", len(ns))
	}
}
