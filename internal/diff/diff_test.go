package diff_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/diff"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestCompare(t *testing.T) {
	prev := map[string]scan.Finding{
		"a": {Kind: scan.KindVuln, VulnID: "CVE-1", Summary: "old", Severity: "high", Source: "nvd"},
		"b": {Kind: scan.KindVuln, VulnID: "CVE-2", Summary: "keep", Severity: "low", Source: "nvd"},
	}
	latest := map[string]scan.Finding{
		"b": {Kind: scan.KindVuln, VulnID: "CVE-2", Summary: "keep", Severity: "low", Source: "nvd"},
		"c": {Kind: scan.KindVuln, VulnID: "CVE-3", Summary: "new", Severity: "crit", Source: "osv"},
	}
	r := diff.Compare(prev, latest)
	if len(r.Added) != 1 || r.Added[0].VulnID != "CVE-3" {
		t.Fatalf("added = %+v", r.Added)
	}
	if len(r.Removed) != 1 || r.Removed[0].VulnID != "CVE-1" {
		t.Fatalf("removed = %+v", r.Removed)
	}
	if r.Kept != 1 {
		t.Fatalf("kept = %d", r.Kept)
	}
	var buf bytes.Buffer
	diff.Write(&buf, r)
	if !strings.Contains(buf.String(), "+1") || !strings.Contains(buf.String(), "CVE-3") {
		t.Fatalf("write = %q", buf.String())
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	findings := []scan.Finding{{
		Kind: scan.KindSecret, RuleID: "aws-key", Summary: "secret", Severity: "high", Source: "secrets", Path: "a.env", Line: 2,
	}}
	raw, err := diff.SnapshotJSON(findings)
	if err != nil {
		t.Fatal(err)
	}
	set, err := diff.SetFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	fp := diff.Fingerprint(findings[0])
	if _, ok := set[fp]; !ok {
		t.Fatalf("missing fingerprint %q in %v", fp, set)
	}
}
