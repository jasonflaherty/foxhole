package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
)

func TestScanHistory(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	ctx := context.Background()
	id, err := database.StartScanHistory(ctx, "/tmp/app")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.FinishScanHistory(ctx, id, 2, "archive/x", `[{"kind":"vuln"}]`, "ok"); err != nil {
		t.Fatal(err)
	}
	rows, err := database.ListScanHistory(ctx, "/tmp/app", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].FindingCount != 2 || rows[0].FindingsJSON == "" {
		t.Fatalf("rows = %+v", rows)
	}

	id2, err := database.StartScanHistory(ctx, "/tmp/app")
	if err != nil {
		t.Fatal(err)
	}
	_ = database.FinishScanHistory(ctx, id2, 1, "", `[]`, "ok")

	latest, prev, err := database.LastTwoScans(ctx, "/tmp/app")
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || prev == nil || latest.ID != id2 || prev.ID != id {
		t.Fatalf("latest=%v prev=%v", latest, prev)
	}
}
