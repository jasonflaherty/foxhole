package triage_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/triage"
)

func TestGenerateGroups(t *testing.T) {
	result := &scan.Result{
		Target: "/app",
		Findings: []scan.Finding{
			{Kind: scan.KindVuln, VulnID: "CVE-1", Severity: "high", Summary: "a", Source: "nvd",
				Package: scan.DiscoveredPackage{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}},
			{Kind: scan.KindVuln, VulnID: "CVE-2", Severity: "high", Summary: "b", Source: "nvd",
				Package: scan.DiscoveredPackage{Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}},
			{Kind: scan.KindSecret, RuleID: "tok", Severity: "critical", Summary: "s", Source: "secrets"},
		},
	}
	rep, err := triage.Generate(context.Background(), result, triage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Groups) != 2 {
		t.Fatalf("groups = %d want 2", len(rep.Groups))
	}
	if !strings.Contains(rep.SuppressYAML, "suppressions:") {
		t.Fatalf("yaml = %s", rep.SuppressYAML)
	}
	draft := triage.FindingDraft(rep, result.Findings[0])
	if draft == "" {
		t.Fatal("empty draft")
	}
}
