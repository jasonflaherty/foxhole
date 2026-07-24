package archive_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jasonflaherty/foxhole/internal/archive"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestWrite(t *testing.T) {
	base := t.TempDir()
	when := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	result := &scan.Result{
		Target:   "/tmp/app",
		Packages: 1,
		Findings: []scan.Finding{{
			Kind:     scan.KindVuln,
			VulnID:   "CVE-2024-0001",
			Summary:  "test",
			Severity: "high",
			Source:   "nvd",
		}},
	}
	dir, err := archive.Write(base, result, when)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(base, "2026", "07", "23")
	if dir != want {
		t.Fatalf("dir = %q, want %q", dir, want)
	}
	for _, name := range []string{"scan.json", "scan.html", "scan.md", "scan.sarif", "scan.txt"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}
