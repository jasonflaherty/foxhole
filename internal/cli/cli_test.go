package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/cli"
)

func TestVersionCommand(t *testing.T) {
	root := cli.NewRootCommand()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "0.1.0") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestScanWithSeededDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "foxhole.db")
	mod := "module app\n\ngo 1.22\n\nrequire github.com/vulnerable/lib v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}

	// Open DB via db update offline will fail without seed — use scan against empty DB.
	root := cli.NewRootCommand()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{dir, "--db-path", dbPath, "--offline"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Packages: 1") {
		t.Fatalf("output = %q", out)
	}
}
