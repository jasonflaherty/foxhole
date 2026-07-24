package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/cli"
)

func TestDBUpdateOfflineSeedsAndScan(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "foxhole.db")
	mod := "module app\n\ngo 1.22\n\nrequire github.com/vulnerable/lib v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRootCommand()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"db", "update", "--db-path", dbPath, "--offline"})
	if err := root.Execute(); err != nil {
		t.Fatalf("db update: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "osv:") || !strings.Contains(out, "nvd:") {
		t.Fatalf("update output = %q", out)
	}

	root2 := cli.NewRootCommand()
	buf2 := new(bytes.Buffer)
	root2.SetOut(buf2)
	root2.SetArgs([]string{"db", "verify", "--db-path", dbPath})
	if err := root2.Execute(); err != nil {
		t.Fatalf("db verify: %v", err)
	}
	if !strings.Contains(buf2.String(), "database integrity: ok") {
		t.Fatalf("verify output = %q", buf2.String())
	}

	root3 := cli.NewRootCommand()
	buf3 := new(bytes.Buffer)
	root3.SetOut(buf3)
	root3.SetArgs([]string{dir, "--db-path", dbPath, "--offline"})
	if err := root3.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(buf3.String(), "GO-2024-TEST") && !strings.Contains(buf3.String(), "CVE-2024-9999") {
		t.Fatalf("scan output = %q", buf3.String())
	}
}
