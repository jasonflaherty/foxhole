package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/diff"
	"github.com/jasonflaherty/foxhole/internal/notify"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

type ghDiffRoundTrip func(*http.Request) (*http.Response, error)

func (f ghDiffRoundTrip) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestGitHubDiffOpenAndClose(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	var created int
	client := ghDiffRoundTrip(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/issues"):
			created++
			body := `{"number":42}`
			return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		case req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/comments"):
			return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		case req.Method == http.MethodPatch:
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		default:
			b, _ := json.Marshal(map[string]string{"error": req.Method + " " + req.URL.Path})
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
		}
	})

	added := scan.Finding{Kind: scan.KindVuln, VulnID: "CVE-NEW", Severity: "high", Summary: "n", Source: "nvd"}
	n := notify.GitHubDiffNotifier{
		Token:  "t",
		Repo:   "o/r",
		Client: client,
		DB:     database,
		Previous: map[string]scan.Finding{},
	}
	result := &scan.Result{Target: "/app", Findings: []scan.Finding{added}}
	if err := n.Notify(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if created != 1 {
		t.Fatalf("created = %d", created)
	}
	fp := diff.Fingerprint(added)
	ref, err := database.GetGitHubIssue(context.Background(), fp, "o/r")
	if err != nil || ref == nil || ref.IssueNumber != 42 {
		t.Fatalf("ref = %+v err=%v", ref, err)
	}

	// Second run with empty findings closes the issue.
	n.Previous = map[string]scan.Finding{fp: added}
	if err := n.Notify(context.Background(), &scan.Result{Target: "/app"}); err != nil {
		t.Fatal(err)
	}
}
