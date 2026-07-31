package ghsa_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
	"github.com/jasonflaherty/foxhole/pkg/provider/ghsa"
)

func TestGHSAMetadataAndUpdate(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	p := ghsa.New(database)
	meta := p.Metadata()
	if meta.ID != "ghsa" || meta.Name == "" {
		t.Fatalf("metadata = %+v", meta)
	}
	if err := p.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := p.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Records < 0 {
		t.Fatalf("update = %+v", res)
	}
	out, err := p.Search(context.Background(), provider.PackageQuery{Ecosystem: "Go", Name: "none", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		out = []provider.Result{}
	}
	_ = out
}
