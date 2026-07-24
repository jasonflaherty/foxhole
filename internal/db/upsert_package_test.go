package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
)

// Reproduces the Juice Shop CI failure: after inserting an advisory, UpsertPackage
// ON CONFLICT must still return a real packages.id (not a stale LastInsertId).
func TestUpsertPackageIDStableAfterAdvisoryInsert(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()

	pkg := db.PackageRef{Ecosystem: "npm", Name: "lodash-es", Version: ""}
	id1, err := database.UpsertPackage(ctx, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertAdvisory(ctx, "GHSA-r5fr-rjxr-66jc", "osv", "test", "HIGH", "", "", "[]", ""); err != nil {
		t.Fatal(err)
	}
	id2, err := database.UpsertPackage(ctx, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("package id changed after advisory insert: %d -> %d", id1, id2)
	}
	if err := database.LinkPackageVuln(ctx, id2, "GHSA-r5fr-rjxr-66jc", "advisory", "", "1.0.0"); err != nil {
		t.Fatalf("LinkPackageVuln FK failed: %v", err)
	}
}
