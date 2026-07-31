package policy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestSuppressionsExpiry(t *testing.T) {
	findings := []scan.Finding{
		{Kind: scan.KindVuln, VulnID: "CVE-2024-0001", Severity: "high", Summary: "a", Source: "nvd"},
		{Kind: scan.KindVuln, VulnID: "CVE-2024-0002", Severity: "high", Summary: "b", Source: "nvd"},
	}
	now, err := time.Parse(time.RFC3339, "2026-06-01T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	p := policy.Policy{
		FailOn: "high",
		Suppressions: []policy.Suppression{
			{ID: "CVE-2024-0001", Until: "2026-12-01", Ticket: "SEC-1", Reason: "vendor patch"},
			{ID: "CVE-2024-0002", Until: "2025-01-01", Ticket: "SEC-2", Reason: "expired"},
		},
	}
	r := policy.EvaluateAt(p, findings, now)
	if !r.Failed || len(r.Violations) != 1 || r.Violations[0].VulnID != "CVE-2024-0002" {
		t.Fatalf("result = %+v", r)
	}
	if len(r.UsedSupp) != 1 || r.UsedSupp[0].Ticket != "SEC-1" {
		t.Fatalf("used = %+v", r.UsedSupp)
	}
}

func TestLoadDirMerge(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("secrets.yaml", "fail_on: medium\nkinds:\n  - secret\n")
	write("vulns.yaml", "fail_on: high\nkinds:\n  - vuln\nsuppressions:\n  - id: CVE-1\n    until: \"2099-01-01\"\n    ticket: T-1\n    reason: ok\n")
	p, err := policy.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// medium is stricter than high (fails on more severities)
	if p.FailOn != "medium" {
		t.Fatalf("fail_on = %q want medium", p.FailOn)
	}
	kindSet := map[string]bool{}
	for _, k := range p.Kinds {
		kindSet[k] = true
	}
	if !kindSet["secret"] || !kindSet["vuln"] {
		t.Fatalf("kinds = %#v", p.Kinds)
	}
	if len(p.Suppressions) != 1 || p.Suppressions[0].Ticket != "T-1" {
		t.Fatalf("suppressions = %+v", p.Suppressions)
	}
}

func TestFingerprintStable(t *testing.T) {
	t.Parallel()
	p := policy.Policy{ID: "org", Version: "1", FailOn: "high", Kinds: []string{"vuln", "secret"}}
	a, err := policy.Fingerprint(p)
	if err != nil || a == "" {
		t.Fatalf("fp a: %v %q", err, a)
	}
	b, err := policy.Fingerprint(p)
	if err != nil || b != a {
		t.Fatalf("fp not stable: %q vs %q err=%v", a, b, err)
	}
	p.Version = "2"
	c, err := policy.Fingerprint(p)
	if err != nil || c == a {
		t.Fatalf("fp should change on version: %q vs %q", a, c)
	}
}
