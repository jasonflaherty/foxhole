package remediate_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/remediate"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestGenerateRuleBased(t *testing.T) {
	rep, err := remediate.Generate(context.Background(), &scan.Result{
		Target: "/app",
		Findings: []scan.Finding{
			{Kind: scan.KindVuln, VulnID: "CVE-1", Package: scan.DiscoveredPackage{Name: "lib", Version: "1.0"}, Fixed: "1.1", Summary: "x", Severity: "high", Source: "nvd", InKEV: true},
			{Kind: scan.KindSecret, RuleID: "aws", Summary: "key", Severity: "critical", Source: "secrets"},
		},
	}, remediate.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Suggestions) != 2 {
		t.Fatalf("got %d", len(rep.Suggestions))
	}
	if !strings.Contains(rep.Suggestions[0].Actions[0], "KEV") && !strings.Contains(strings.Join(rep.Suggestions[0].Actions, " "), "KEV") {
		t.Fatalf("expected KEV priority: %#v", rep.Suggestions[0].Actions)
	}
	var buf bytes.Buffer
	if err := remediate.WriteMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Remediate") {
		t.Fatal(buf.String())
	}
}
