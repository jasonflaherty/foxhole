package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/cli"
)

func TestHistoryAndDiffCommands(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "foxhole.db")
	mod := "module app\n\ngo 1.22\n\nrequire github.com/vulnerable/lib v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		t.Helper()
		root := cli.NewRootCommand()
		buf := new(bytes.Buffer)
		root.SetOut(buf)
		root.SetErr(buf)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("args %v: %v\n%s", args, err, buf.String())
		}
		return buf.String()
	}

	out := run(dir, "--db-path", dbPath, "--offline", "--archive", "--archive-dir", filepath.Join(dir, "archive"))
	if !strings.Contains(out, "Archived to") {
		t.Fatalf("expected archive line, got %q", out)
	}
	_ = run(dir, "--db-path", dbPath, "--offline")

	hist := run("history", dir, "--db-path", dbPath, "--limit", "5")
	if !strings.Contains(hist, "FINDINGS") {
		t.Fatalf("history = %q", hist)
	}

	diffOut := run("diff", "last", dir, "--db-path", dbPath)
	if !strings.Contains(diffOut, "Diff:") && !strings.Contains(diffOut, "Comparing") {
		t.Fatalf("diff = %q", diffOut)
	}
}
