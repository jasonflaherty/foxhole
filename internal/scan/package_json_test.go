package scan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestParsePackageJSONDirectOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pkgJSON := `{
  "name": "app",
  "dependencies": {"lodash": "^4.17.21", "express": "~4.18.0"},
  "devDependencies": {"mocha": "10.0.0"}
}`
	lock := `{"packages":{"node_modules/lodash":{"version":"4.17.21"},"node_modules/left-pad":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default scan includes package.json even when a lockfile is present.
	all, err := scan.NewFilesystemScanner().Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 3 {
		t.Fatalf("default scan pkgs = %#v", all)
	}

	direct, err := scan.NewFilesystemScanner().ScanWithOptions(dir, scan.ScanOptions{DirectOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 3 {
		t.Fatalf("direct pkgs = %#v", direct)
	}

	limited, err := scan.NewFilesystemScanner().ScanWithOptions(dir, scan.ScanOptions{MaxPackages: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 1 {
		t.Fatalf("limited = %d", len(limited))
	}
}

func TestScanPackageJSONWithoutLockfile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pkgJSON := `{"dependencies":{"lodash":"4.17.21"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := scan.NewFilesystemScanner().Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "lodash" {
		t.Fatalf("pkgs = %#v", pkgs)
	}
}
