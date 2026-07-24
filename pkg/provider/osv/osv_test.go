package osv_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
	"github.com/jasonflaherty/foxhole/pkg/provider/osv"
)

func TestOSVSeedUpdateSearchVerify(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	seed, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "fixtures", "osv_seed.json"))
	if err != nil {
		// fallback when running from module root via go test ./...
		seed, err = os.ReadFile(filepath.Join("testdata", "fixtures", "osv_seed.json"))
		if err != nil {
			seed = []byte(`[{"id":"GO-2024-TEST","ecosystem":"Go","name":"github.com/vulnerable/lib","summary":"Test","severity":"HIGH","aliases":["CVE-2024-9999"],"fixed":"1.2.3"}]`)
		}
	}

	p := osv.New(database, osv.WithSeedAdvisories(seed), osv.WithOffline(true))
	ctx := context.Background()
	if err := p.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := p.Update(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 1 {
		t.Fatalf("records = %d", res.Records)
	}
	if err := p.Verify(ctx); err != nil {
		t.Fatal(err)
	}

	results, err := p.Search(ctx, provider.PackageQuery{
		Ecosystem: "Go",
		Name:      "github.com/vulnerable/lib",
		Version:   "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected search hits")
	}
	if results[0].ID != "GO-2024-TEST" && results[0].ID != "CVE-2024-9999" {
		t.Fatalf("id = %s", results[0].ID)
	}
}

func TestOSVMetadata(t *testing.T) {
	t.Parallel()
	p := osv.New(nil)
	meta := p.Metadata()
	if meta.ID != "osv" {
		t.Fatalf("id = %s", meta.ID)
	}
}
