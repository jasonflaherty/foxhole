package policy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/policy"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestEvaluateFailOnHigh(t *testing.T) {
	findings := []scan.Finding{
		{Kind: scan.KindVuln, VulnID: "CVE-LOW", Severity: "low", Summary: "low", Source: "nvd"},
		{Kind: scan.KindVuln, VulnID: "CVE-HIGH", Severity: "HIGH", Summary: "high", Source: "nvd"},
		{Kind: scan.KindSecret, RuleID: "aws-key", Severity: "critical", Summary: "secret", Source: "secrets"},
	}
	r := policy.Evaluate(policy.Policy{FailOn: "high"}, findings)
	if !r.Failed || len(r.Violations) != 2 {
		t.Fatalf("result = %+v", r)
	}
	if r.ExitCode() != policy.ExitPolicy {
		t.Fatalf("exit = %d", r.ExitCode())
	}
}

func TestEvaluateKindsAndIgnore(t *testing.T) {
	findings := []scan.Finding{
		{Kind: scan.KindVuln, VulnID: "CVE-1", Severity: "high", Summary: "v", Source: "nvd"},
		{Kind: scan.KindSecret, RuleID: "tok", Severity: "high", Summary: "s", Source: "secrets"},
		{Kind: scan.KindEOL, Product: "go", Cycle: "1.20", Severity: "high", Summary: "e", Source: "eol"},
	}
	r := policy.Evaluate(policy.Policy{
		FailOn: "high",
		Kinds:  []string{"vuln", "secret"},
		Ignore: []string{"tok"},
	}, findings)
	if !r.Failed || len(r.Violations) != 1 || r.Violations[0].VulnID != "CVE-1" {
		t.Fatalf("result = %+v", r)
	}
}

func TestEvaluateDisabled(t *testing.T) {
	findings := []scan.Finding{{Kind: scan.KindVuln, VulnID: "X", Severity: "critical", Summary: "x", Source: "nvd"}}
	r := policy.Evaluate(policy.Policy{}, findings)
	if r.Failed {
		t.Fatal("expected disabled")
	}
	r = policy.Evaluate(policy.Policy{FailOn: "none"}, findings)
	if r.Failed {
		t.Fatal("expected none")
	}
}

func TestEvaluateAny(t *testing.T) {
	findings := []scan.Finding{{Kind: scan.KindEOL, Product: "go", Cycle: "1", Severity: "unknown", Summary: "e", Source: "eol"}}
	r := policy.Evaluate(policy.Policy{FailOn: "any"}, findings)
	if !r.Failed {
		t.Fatal("expected any to fail")
	}
}

func TestLoadFileAndWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body := "fail_on: medium\nkinds:\n  - vuln\nignore:\n  - SKIP\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := policy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.FailOn != "medium" || len(p.Kinds) != 1 || p.Ignore[0] != "SKIP" {
		t.Fatalf("loaded = %+v", p)
	}

	r := policy.Evaluate(p, []scan.Finding{
		{Kind: scan.KindVuln, VulnID: "A", Severity: "high", Summary: "a", Source: "nvd"},
	})
	var buf bytes.Buffer
	policy.Write(&buf, r)
	if !strings.Contains(buf.String(), "policy failed") || !strings.Contains(buf.String(), "A") {
		t.Fatalf("write = %q", buf.String())
	}
}

func TestMerge(t *testing.T) {
	p := policy.Merge(policy.Policy{FailOn: "low", Kinds: []string{"vuln"}}, "high", []string{"secret"})
	if p.FailOn != "high" || len(p.Kinds) != 1 || p.Kinds[0] != "secret" {
		t.Fatalf("merge = %+v", p)
	}
}
