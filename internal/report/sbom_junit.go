package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

func writeIndentJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// JUnit writes a JUnit XML report for CI test result parsers.
type JUnit struct{}

func (JUnit) Format() string { return "junit" }

func (JUnit) Write(w io.Writer, result *scan.Result) error {
	type tc struct {
		XMLName xml.Name `xml:"testcase"`
		Name    string   `xml:"name,attr"`
		Class   string   `xml:"classname,attr"`
		Time    string   `xml:"time,attr"`
		Failure *struct {
			Message string `xml:"message,attr"`
			Body    string `xml:",chardata"`
		} `xml:"failure,omitempty"`
	}
	type ts struct {
		XMLName   xml.Name `xml:"testsuite"`
		Name      string   `xml:"name,attr"`
		Tests     int      `xml:"tests,attr"`
		Failures  int      `xml:"failures,attr"`
		TestCases []tc     `xml:"testcase"`
	}
	suite := ts{Name: "foxhole", Tests: len(result.Findings)}
	if len(result.Findings) == 0 {
		suite.Tests = 1
		suite.TestCases = []tc{{Name: "no findings", Class: "foxhole", Time: "0"}}
	}
	for _, f := range result.Findings {
		item := tc{
			Name:  fmt.Sprintf("%s:%s", f.Kind, f.ID()),
			Class: "foxhole." + string(f.Kind),
			Time:  "0",
			Failure: &struct {
				Message string `xml:"message,attr"`
				Body    string `xml:",chardata"`
			}{
				Message: severityOrUnknown(f.Severity) + " " + f.Summary,
				Body:    f.Summary,
			},
		}
		suite.Failures++
		suite.TestCases = append(suite.TestCases, item)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suite)
}

// CycloneDX writes a minimal CycloneDX 1.5 JSON SBOM from discovered packages + vulns.
type CycloneDX struct{}

func (CycloneDX) Format() string { return "cyclonedx" }

func (CycloneDX) Write(w io.Writer, result *scan.Result) error {
	type comp struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl,omitempty"`
	}
	type vuln struct {
		ID     string `json:"id"`
		Source struct {
			Name string `json:"name"`
		} `json:"source"`
		Description string `json:"description,omitempty"`
	}
	type doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Version     int    `json:"version"`
		Metadata    struct {
			Component struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Components      []comp `json:"components"`
		Vulnerabilities []vuln `json:"vulnerabilities,omitempty"`
	}
	var d doc
	d.BOMFormat = "CycloneDX"
	d.SpecVersion = "1.5"
	d.Version = 1
	d.Metadata.Component.Type = "application"
	d.Metadata.Component.Name = result.Target
	seen := map[string]struct{}{}
	for _, f := range result.Findings {
		if f.Package.Name == "" {
			continue
		}
		key := f.Package.Ecosystem + "|" + f.Package.Name + "|" + f.Package.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		d.Components = append(d.Components, comp{
			Type: "library", Name: f.Package.Name, Version: f.Package.Version,
			PURL: purl(f.Package),
		})
	}
	for _, f := range result.Findings {
		if f.Kind != scan.KindVuln {
			continue
		}
		v := vuln{ID: f.ID(), Description: f.Summary}
		v.Source.Name = f.Source
		d.Vulnerabilities = append(d.Vulnerabilities, v)
	}
	return writeIndentJSON(w, d)
}

// SPDX writes a minimal SPDX 2.3 JSON document.
type SPDX struct{}

func (SPDX) Format() string { return "spdx" }

func (SPDX) Write(w io.Writer, result *scan.Result) error {
	type pkg struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo,omitempty"`
		DownloadLocation string `json:"downloadLocation"`
	}
	type doc struct {
		SPDXVersion       string `json:"spdxVersion"`
		DataLicense       string `json:"dataLicense"`
		SPDXID            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		Packages          []pkg  `json:"packages"`
	}
	d := doc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              result.Target,
		DocumentNamespace: "http://foxhole.local/spdx/" + strings.ReplaceAll(result.Target, "/", "-"),
	}
	seen := map[string]struct{}{}
	i := 0
	for _, f := range result.Findings {
		if f.Package.Name == "" {
			continue
		}
		key := f.Package.Name + "@" + f.Package.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		i++
		d.Packages = append(d.Packages, pkg{
			SPDXID: fmt.Sprintf("SPDXRef-Package-%d", i),
			Name:   f.Package.Name, VersionInfo: f.Package.Version,
			DownloadLocation: "NOASSERTION",
		})
	}
	if len(d.Packages) == 0 {
		d.Packages = append(d.Packages, pkg{SPDXID: "SPDXRef-Package-0", Name: result.Target, DownloadLocation: "NOASSERTION"})
	}
	return writeIndentJSON(w, d)
}

func purl(p scan.DiscoveredPackage) string {
	eco := strings.ToLower(p.Ecosystem)
	switch eco {
	case "go":
		return "pkg:golang/" + p.Name + "@" + p.Version
	case "npm":
		return "pkg:npm/" + p.Name + "@" + p.Version
	case "pypi":
		return "pkg:pypi/" + p.Name + "@" + p.Version
	case "crates.io", "cargo":
		return "pkg:cargo/" + p.Name + "@" + p.Version
	default:
		return "pkg:generic/" + p.Name + "@" + p.Version
	}
}
