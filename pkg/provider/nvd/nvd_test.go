package nvd_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
	"github.com/jasonflaherty/foxhole/pkg/provider/nvd"
)

func TestNVDSeedUpdateSearchVerify(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	seed := []byte(`[{"id":"CVE-2024-9999","summary":"Test CVE","severity":"HIGH","cvss_score":7.5}]`)
	p := nvd.New(database, nvd.WithSeedCVEs(seed), nvd.WithOffline(true))
	ctx := context.Background()
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
	results, err := p.Search(ctx, provider.PackageQuery{Ecosystem: "cve", Name: "CVE-2024-9999"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Severity != "HIGH" {
		t.Fatalf("results = %#v", results)
	}
}

func TestNVDOfflineWithoutSeedFails(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	p := nvd.New(database, nvd.WithOffline(true))
	if _, err := p.Update(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}
