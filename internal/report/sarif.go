package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// SARIF writes a SARIF 2.1.0 report for GitHub code scanning compatibility.
type SARIF struct{}

// Format returns the format name.
func (SARIF) Format() string { return "sarif" }

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine,omitempty"`
		} `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

// Write encodes SARIF JSON.
func (SARIF) Write(w io.Writer, result *scan.Result) error {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range result.Findings {
		ruleID := f.ID()
		if ruleID == "" {
			ruleID = string(f.Kind)
		}
		if _, ok := rules[ruleID]; !ok {
			r := sarifRule{ID: ruleID}
			r.ShortDescription.Text = f.Summary
			if r.ShortDescription.Text == "" {
				r.ShortDescription.Text = ruleID
			}
			rules[ruleID] = r
		}
		item := sarifResult{
			RuleID: ruleID,
			Level:  sarifLevel(f.Severity),
		}
		item.Message.Text = f.Summary
		if item.Message.Text == "" {
			item.Message.Text = ruleID
		}
		uri := f.Path
		if uri == "" && f.Package.Path != "" {
			uri = f.Package.Path
		}
		if uri == "" {
			uri = result.Target
		}
		uri = filepath.ToSlash(uri)
		loc := sarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = uri
		if f.Line > 0 {
			loc.PhysicalLocation.Region.StartLine = f.Line
		}
		item.Locations = []sarifLocation{loc}
		results = append(results, item)
	}
	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "foxhole",
				InformationURI: "https://github.com/jasonflaherty/foxhole",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	return nil
}

func sarifLevel(sev string) string {
	switch severityOrUnknown(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}
