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

func TestLastGreenScan(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "green.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	target := "/tmp/green-app"

	failID, err := database.StartScanHistory(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.FinishScanHistory(ctx, failID, 3, "", `[]`, "policy_failed"); err != nil {
		t.Fatal(err)
	}
	greenID, err := database.StartScanHistory(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.FinishScanHistory(ctx, greenID, 0, "", `[]`, "ok"); err != nil {
		t.Fatal(err)
	}
	failAgain, err := database.StartScanHistory(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.FinishScanHistory(ctx, failAgain, 1, "", `[]`, "policy_failed"); err != nil {
		t.Fatal(err)
	}

	got, err := database.LastGreenScan(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != greenID || !got.PolicyPassed {
		t.Fatalf("LastGreenScan = %+v want id=%d", got, greenID)
	}
	missing, err := database.LastGreenScan(ctx, "/tmp/none")
	if err != nil || missing != nil {
		t.Fatalf("missing = %v err=%v", missing, err)
	}
}
