package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestScanLicensesFindsDeclaredHighRisk(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "lic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()
	if err := database.UpsertLicense(ctx, "gpl-3.0", "GNU GPL v3", "GPL-3.0", "high", true); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE\nVersion 3\nGPL-3.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs := []scan.DiscoveredPackage{{
		Ecosystem: "npm", Name: "evil-lib", Version: "1.0.0",
		Path: filepath.Join(root, "package.json"), License: "GPL-3.0",
	}}
	findings, err := scan.ScanLicenses(ctx, database, root, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected LICENSE file + declared package findings, got %#v", findings)
	}
	kinds := 0
	for _, f := range findings {
		if f.Kind != scan.KindLicense {
			t.Fatalf("kind = %s", f.Kind)
		}
		kinds++
	}
	if kinds == 0 {
		t.Fatal("no license findings")
	}
}
