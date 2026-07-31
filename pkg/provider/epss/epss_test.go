package epss_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider/epss"
)

func TestEPSSSeedUpdate(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	p := epss.New(database, epss.WithOffline(true))
	meta := p.Metadata()
	if meta.ID != "epss" {
		t.Fatalf("metadata = %+v", meta)
	}
	res, err := p.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Records < 1 {
		t.Fatalf("expected seeded EPSS rows, got %d", res.Records)
	}
	n, err := database.CountEPSS(context.Background())
	if err != nil || n < 1 {
		t.Fatalf("CountEPSS = %d err=%v", n, err)
	}
}
