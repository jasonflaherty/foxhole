package report_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestWriteSplitJSON(t *testing.T) {
	dir := t.TempDir()
	result := &scan.Result{
		Target:   "/app",
		Packages: 1,
		Findings: []scan.Finding{
			{Kind: scan.KindVuln, VulnID: "CVE-1", Severity: "high", Summary: "v", Source: "nvd"},
			{Kind: scan.KindSecret, RuleID: "tok", Severity: "critical", Summary: "s", Source: "secrets"},
		},
	}
	if err := report.WriteSplitJSON(result, dir, os.Stdout); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"foxhole-vulns.json",
		"foxhole-secrets.json",
		"foxhole-eol.json",
		"foxhole-misconfig.json",
		"foxhole-licenses.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}
