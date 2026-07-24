package evidence_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/evidence"
	"github.com/jasonflaherty/foxhole/internal/policy"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestWriteEvidencePack(t *testing.T) {
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	_ = database.UpdateDBHash(context.Background())

	out := filepath.Join(dir, "evidence")
	result := &scan.Result{
		Target:     "/app",
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Findings: []scan.Finding{
			{Kind: scan.KindVuln, VulnID: "CVE-1", Severity: "high", Summary: "x", Source: "nvd"},
		},
	}
	pol := policy.Policy{ID: "pack", Version: "1", FailOn: "high"}
	decision := policy.Evaluate(pol, result.Findings)
	path, err := evidence.Write(context.Background(), evidence.Input{
		Result:   result,
		Policy:   pol,
		Decision: decision,
		Database: database,
		MaxDBAge: "720h",
		OutDir:   out,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "policy.json", "result.json", "findings.sarif", "suppressions.json"} {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(path, "manifest.json"))
	var mani evidence.Manifest
	if err := json.Unmarshal(b, &mani); err != nil {
		t.Fatal(err)
	}
	if mani.PolicyFP == "" || !mani.PolicyFailed {
		t.Fatalf("manifest = %+v", mani)
	}
}
