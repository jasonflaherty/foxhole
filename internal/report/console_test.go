package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func sampleResult() *scan.Result {
	return &scan.Result{
		Target:     "/tmp/app",
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		Packages:   2,
		Findings: []scan.Finding{{
			Kind:     scan.KindVuln,
			Package:  scan.DiscoveredPackage{Ecosystem: "Go", Name: "example.com/x", Version: "1.0.0"},
			VulnID:   "CVE-2024-1",
			Summary:  "boom",
			Severity: "HIGH",
			Source:   "osv",
		}},
	}
}

func TestConsoleWrite(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := (report.Console{}).Write(&buf, sampleResult()); err != nil {
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
	if err := (report.Console{}).Write(&buf, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Fatalf("output = %s", buf.String())
	}
}

func TestJSONAndSARIF(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := (report.JSON{}).Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var env report.Envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.SchemaVersion != report.SchemaVersion || env.Tool != "foxhole" || env.Result == nil {
		t.Fatalf("envelope = %+v", env)
	}
	if len(env.Result.Findings) != 1 {
		t.Fatalf("findings = %d", len(env.Result.Findings))
	}

	buf.Reset()
	if err := (report.SARIF{}).Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"version": "2.1.0"`) {
		t.Fatalf("sarif = %s", buf.String())
	}
}

func TestParseFormats(t *testing.T) {
	t.Parallel()
	got := report.ParseFormats("json, html, json")
	if len(got) != 2 || got[0] != "json" || got[1] != "html" {
		t.Fatalf("got = %#v", got)
	}
}

func TestMarkdownHTML(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := (report.Markdown{}).Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "# Foxhole scan") {
		t.Fatal(buf.String())
	}
	buf.Reset()
	if err := (report.HTML{}).Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<table>") {
		t.Fatal(buf.String())
	}
}

func TestJUnitCycloneDXSPDX(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := (report.JUnit{}).Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<testsuite") || !strings.Contains(out, "CVE-2024-1") {
		t.Fatalf("junit = %s", out)
	}

	buf.Reset()
	if err := (report.CycloneDX{}).Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	cdx := buf.String()
	if !strings.Contains(cdx, `"bomFormat": "CycloneDX"`) && !strings.Contains(cdx, `"bomFormat":"CycloneDX"`) {
		// encoder may indent
		if !strings.Contains(cdx, "CycloneDX") {
			t.Fatalf("cyclonedx = %s", cdx)
		}
	}
	if !strings.Contains(cdx, "CVE-2024-1") {
		t.Fatalf("cyclonedx missing vuln: %s", cdx)
	}

	buf.Reset()
	if err := (report.SPDX{}).Write(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	spdx := buf.String()
	if !strings.Contains(spdx, "SPDX-2.3") && !strings.Contains(spdx, "spdxVersion") {
		t.Fatalf("spdx = %s", spdx)
	}
}
