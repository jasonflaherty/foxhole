package cli_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/dbbundle"
)

func TestDBExportImportThenScan(t *testing.T) {
	dir := t.TempDir()
	srcDB := filepath.Join(dir, "src.db")
	destDB := filepath.Join(dir, "dest.db")
	work := filepath.Join(dir, "app")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte("module app\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	bin := buildFoxhole(t, dir)
	seed := exec.Command(bin, "db", "update", work, "--db-path", srcDB, "--offline")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}

	src, err := db.Open(srcDB)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle.tar.gz")
	if _, err := dbbundle.Export(context.Background(), src, bundle); err != nil {
		t.Fatal(err)
	}
	_ = src.Close()

	if _, err := dbbundle.Import(bundle, destDB); err != nil {
		t.Fatal(err)
	}

	scan := exec.Command(bin, work, "--db-path", destDB, "--offline", "--secrets=false", "--eol=false",
		"--max-db-age", "720h", "--report", "console")
	if out, err := scan.CombinedOutput(); err != nil {
		t.Fatalf("scan after import: %v\n%s", err, out)
	}
}

func TestPolicyValidateCommand(t *testing.T) {
	dir := t.TempDir()
	bin := buildFoxhole(t, dir)
	repoRoot := filepath.Join("..", "..")
	pack := filepath.Join(repoRoot, "examples", "policy-pack")

	cmd := exec.Command(bin, "policy", "validate", pack)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("validate: %v\nstdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "fingerprint=") {
		t.Fatalf("missing fingerprint: %s", out)
	}
}
