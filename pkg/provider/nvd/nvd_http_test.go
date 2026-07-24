package nvd_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider/nvd"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestNVDFetchRecent(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	body := `{
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2024-1111",
	      "published": "2024-01-01T00:00:00.000",
	      "lastModified": "2024-01-02T00:00:00.000",
	      "descriptions": [{"lang":"en","value":"example"}],
	      "metrics": {
	        "cvssMetricV31": [{
	          "cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}
	        }]
	      }
	    }
	  }]
	}`
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("apiKey") != "secret" {
			t.Fatalf("missing api key header")
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
			Header:     make(http.Header),
		}, nil
	})

	p := nvd.New(database, nvd.WithHTTPClient(client), nvd.WithAPIKey("secret"), nvd.WithRecentDays(3))
	res, err := p.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 1 {
		t.Fatalf("records = %d", res.Records)
	}
	if err := p.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNVDFetchErrorStatus(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 403,
			Body:       io.NopCloser(bytes.NewReader([]byte("denied"))),
			Header:     make(http.Header),
		}, nil
	})
	p := nvd.New(database, nvd.WithHTTPClient(client))
	if _, err := p.Update(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}
