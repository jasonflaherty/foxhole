package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestConsoleWrite(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	result := &scan.Result{
		Target:     "/tmp/app",
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Packages:   2,
		Findings: []scan.Finding{{
			Package:  scan.DiscoveredPackage{Ecosystem: "Go", Name: "example.com/x", Version: "1.0.0"},
			VulnID:   "CVE-2024-1",
			Summary:  "boom",
			Severity: "HIGH",
			Source:   "osv",
		}},
	}
	if err := (report.Console{Out: &buf}).Write(result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "CVE-2024-1") || !strings.Contains(out, "Findings: 1") {
		t.Fatalf("output = %s", out)
	}
}

func TestConsoleNoFindings(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	result := &scan.Result{Target: ".", StartedAt: time.Now(), FinishedAt: time.Now()}
	if err := (report.Console{Out: &buf}).Write(result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No vulnerabilities") {
		t.Fatalf("output = %s", buf.String())
	}
}
