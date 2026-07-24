package scan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestParseGoMod(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := `module example.com/app

go 1.22

require (
        github.com/gin-gonic/gin v1.9.1
        golang.org/x/crypto v0.17.0 // indirect
)

require github.com/stretchr/testify v1.8.4
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := scan.NewFilesystemScanner().Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) < 3 {
		t.Fatalf("packages = %d, want >= 3: %#v", len(pkgs), pkgs)
	}
	found := map[string]string{}
	for _, p := range pkgs {
		if p.Ecosystem != "Go" {
			t.Fatalf("ecosystem = %s", p.Ecosystem)
		}
		found[p.Name] = p.Version
	}
	if found["github.com/gin-gonic/gin"] != "v1.9.1" {
		t.Fatalf("gin version = %q", found["github.com/gin-gonic/gin"])
	}
}

func TestParseRequirements(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := `# deps
requests==2.31.0
flask>=2.0.0
`
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := scan.NewFilesystemScanner().Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("packages = %d", len(pkgs))
	}
}

func TestParsePackageLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := `{
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0o644); err != nil {
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

func TestSkipGitAndNodeModules(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o755)
	if err := os.WriteFile(filepath.Join(dir, ".git", "go.mod"), []byte("module x\nrequire github.com/a/b v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "x", "go.mod"), []byte("module y\nrequire github.com/c/d v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module app\nrequire github.com/e/f v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := scan.NewFilesystemScanner().Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "github.com/e/f" {
		t.Fatalf("pkgs = %#v", pkgs)
	}
}
