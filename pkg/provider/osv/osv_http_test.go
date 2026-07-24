package osv_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
	"github.com/jasonflaherty/foxhole/pkg/provider/osv"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestOSVFetchPackages(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	body := `{
	  "vulns": [{
	    "id": "GO-2024-API",
	    "summary": "from api",
	    "aliases": ["CVE-2024-2222"],
	    "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	    "affected": [{
	      "package": {"name":"github.com/foo/bar","ecosystem":"Go"},
	      "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]
	    }]
	  }]
	}`
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
			Header:     make(http.Header),
		}, nil
	})

	pkgs := []provider.PackageQuery{{Ecosystem: "Go", Name: "github.com/foo/bar", Version: "1.0.0"}}
	p := osv.New(database, osv.WithHTTPClient(client), osv.WithPackages(pkgs))
	res, err := p.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 1 {
		t.Fatalf("records = %d", res.Records)
	}
	hits, err := p.Search(context.Background(), pkgs[0])
	if err != nil || len(hits) == 0 {
		t.Fatalf("search hits=%v err=%v", hits, err)
	}
}

func TestOSVEmptyUpdate(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	p := osv.New(database)
	res, err := p.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 0 {
		t.Fatalf("records = %d", res.Records)
	}
	if err := p.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOSVAPIError(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(bytes.NewReader([]byte("fail"))),
			Header:     make(http.Header),
		}, nil
	})
	pkgs := []provider.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}
	p := osv.New(database, osv.WithHTTPClient(client), osv.WithPackages(pkgs))
	if _, err := p.Update(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}
