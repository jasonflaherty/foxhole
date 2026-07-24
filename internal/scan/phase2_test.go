package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestSecretsScannerFindsAWSKey(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()
	if err := database.UpsertSecretRule(ctx, db.SecretRule{
		ID: "aws-access-key", Name: "AWS Access Key ID",
		Pattern: `AKIA[0-9A-Z]{16}`, Severity: "critical", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	content := "const key = \"AKIAIOSFODNN7EXAMPLE\";\n"
	if err := os.WriteFile(filepath.Join(dir, "config.js"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := scan.NewSecretsScanner(database).Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Kind != scan.KindSecret {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestEOLCheckerDetectsOldGo(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()
	if err := database.UpsertEOL(ctx, db.EOLRecord{
		Product: "go", Cycle: "1.20", EOL: "2024-02-01", Latest: "1.20.14",
	}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	modPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(modPath, []byte("module x\n\ngo 1.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs := []scan.DiscoveredPackage{{Ecosystem: "Go", Name: "example.com/x", Version: "v1.0.0", Path: modPath}}
	checker := scan.NewEOLChecker(database)
	// force "now" after EOL by relying on real clock (2026+)
	if time.Now().Before(time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)) {
		t.Skip("clock before go 1.20 EOL")
	}
	findings, err := checker.Check(ctx, dir, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected EOL finding")
	}
	found := false
	for _, f := range findings {
		if f.Kind == scan.KindEOL && f.Product == "go" {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %#v", findings)
	}
}
