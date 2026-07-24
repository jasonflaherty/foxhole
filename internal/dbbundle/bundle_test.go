package dbbundle_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/dbbundle"
)

func TestExportImport(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	database, err := db.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateDBHash(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	// Re-open for export while file stable
	database, err = db.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle.tar.gz")
	path, err := dbbundle.Export(context.Background(), database, bundle)
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}
	if path != bundle {
		t.Fatalf("path = %s", path)
	}

	dest := filepath.Join(dir, "dest.db")
	meta, err := dbbundle.Import(bundle, dest)
	if err != nil {
		t.Fatal(err)
	}
	if meta.DBFileSHA256 == "" {
		t.Fatal("missing digest")
	}
	imported, err := db.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = imported.Close() }()
	if _, ok, err := imported.LastSyncAt(context.Background()); err != nil || !ok {
		t.Fatalf("last sync ok=%v err=%v", ok, err)
	}
}
