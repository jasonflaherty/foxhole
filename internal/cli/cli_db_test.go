package cli_test

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/cli"
)

func TestDBUpdateAndVerifyMissingHashes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")

	// Fresh DB with no provider hashes should fail verify.
	root := cli.NewRootCommand()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"db", "verify", "--db-path", dbPath})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected verify failure")
	}
	if !strings.Contains(err.Error(), "missing content hash") {
		t.Fatalf("unexpected error: %v", err)
	}
}
