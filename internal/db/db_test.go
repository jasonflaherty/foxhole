package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
)

func TestOpenMigrateAndMetadata(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "foxhole.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	ctx := context.Background()
	if err := database.SetMetadata(ctx, "hello", "world"); err != nil {
		t.Fatal(err)
	}
	val, ok, err := database.GetMetadata(ctx, "hello")
	if err != nil || !ok || val != "world" {
		t.Fatalf("GetMetadata = %q ok=%v err=%v", val, ok, err)
	}

	schema, ok, err := database.GetMetadata(ctx, "schema_version")
	if err != nil || !ok || schema != "1" {
		t.Fatalf("schema_version = %q ok=%v err=%v", schema, ok, err)
	}
}

func TestPackageVulnRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "foxhole.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()

	score := 9.8
	if err := database.UpsertCVE(ctx, "CVE-2024-0001", "nvd", "critical bug", "CRITICAL", &score, "", "", ""); err != nil {
		t.Fatal(err)
	}
	pkgID, err := database.UpsertPackage(ctx, db.PackageRef{Ecosystem: "Go", Name: "example.com/lib", Version: ""})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.LinkPackageVuln(ctx, pkgID, "CVE-2024-0001", "cve", "", "1.2.3"); err != nil {
		t.Fatal(err)
	}

	findings, err := database.SearchPackageVulns(ctx, db.PackageRef{Ecosystem: "Go", Name: "example.com/lib", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].VulnID != "CVE-2024-0001" {
		t.Fatalf("vuln = %s", findings[0].VulnID)
	}
}

func TestSearchCVEAndCounts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "foxhole.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()
	score := 5.0
	if err := database.UpsertCVE(ctx, "CVE-2023-1", "nvd", "x", "MEDIUM", &score, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertAdvisory(ctx, "GHSA-x", "osv", "y", "LOW", "", "", "[]", ""); err != nil {
		t.Fatal(err)
	}
	f, err := database.SearchCVE(ctx, "cve-2023-1")
	if err != nil || f == nil || f.VulnID != "CVE-2023-1" {
		t.Fatalf("SearchCVE = %#v err=%v", f, err)
	}
	cves, adv, err := database.CountVulns(ctx)
	if err != nil || cves != 1 || adv != 1 {
		t.Fatalf("counts cves=%d adv=%d err=%v", cves, adv, err)
	}
	if err := database.UpsertProvider(ctx, "nvd", "NVD", "2", "hash", "ok"); err != nil {
		t.Fatal(err)
	}
	_, ok, err := database.LastProviderUpdate(ctx, "nvd")
	if err != nil || !ok {
		t.Fatalf("LastProviderUpdate ok=%v err=%v", ok, err)
	}
	if err := database.UpdateDBHash(ctx); err != nil {
		t.Fatal(err)
	}
	sum, err := db.FileSHA256(path)
	if err != nil || len(sum) != 64 {
		t.Fatalf("FileSHA256 = %q err=%v", sum, err)
	}
}

func TestProviderUpsertAndIntegrity(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "foxhole.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()

	if err := database.UpsertProvider(ctx, "osv", "OSV", "1", "abc", "ok"); err != nil {
		t.Fatal(err)
	}
	hash, ok, err := database.ProviderSHA256(ctx, "osv")
	if err != nil || !ok || hash != "abc" {
		t.Fatalf("hash=%q ok=%v err=%v", hash, ok, err)
	}
	if err := database.UpdateDBHash(ctx); err != nil {
		t.Fatal(err)
	}
	ok, err = database.IntegrityOK(ctx)
	if err != nil || !ok {
		t.Fatalf("IntegrityOK=%v err=%v", ok, err)
	}
}
