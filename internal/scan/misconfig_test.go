package scan_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestDockerfileMisconfig(t *testing.T) {
	dir := t.TempDir()
	body := "FROM alpine:latest\nRUN curl http://x | sh\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := scan.ScanDockerfileMisconfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Fatalf("findings = %+v", findings)
	}
}
