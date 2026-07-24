package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
)

func TestCloseNilAndSearchMiss(t *testing.T) {
	t.Parallel()
	var nilDB *db.DB
	if err := nilDB.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := db.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	ctx := context.Background()
	f, err := database.SearchCVE(ctx, "CVE-NOPE")
	if err != nil || f != nil {
		t.Fatalf("expected miss, got %#v err=%v", f, err)
	}
	findings, err := database.SearchPackageVulns(ctx, db.PackageRef{Ecosystem: "Go", Name: "none", Version: "1"})
	if err != nil || len(findings) != 0 {
		t.Fatalf("findings=%v err=%v", findings, err)
	}
	_, ok, err := database.LastProviderUpdate(ctx, "missing")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if database.Path() == "" {
		t.Fatal("empty path")
	}
	if database.SQL() == nil {
		t.Fatal("nil sql")
	}
	ok, err = database.IntegrityOK(ctx)
	if err != nil || !ok {
		t.Fatalf("integrity ok=%v err=%v", ok, err)
	}
}
