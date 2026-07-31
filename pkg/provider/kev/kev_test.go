package kev_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider/kev"
)

func TestKEVOfflineSeedUpdate(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	p := kev.New(database, kev.WithOffline(true))
	meta := p.Metadata()
	if meta.ID != "kev" {
		t.Fatalf("metadata = %+v", meta)
	}
	res, err := p.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Records < 1 {
		t.Fatalf("expected seeded KEV rows, got %d", res.Records)
	}
	n, err := database.CountKEV(context.Background())
	if err != nil || n < 1 {
		t.Fatalf("CountKEV = %d err=%v", n, err)
	}
}
