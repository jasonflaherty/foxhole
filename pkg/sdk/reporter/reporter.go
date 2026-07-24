// Package reporter defines the Reporter SDK for Foxhole plugins.
// Reporters format scan findings into various output formats.
package reporter

import (
	"io"
)

// Finding represents a scan result (minimal interface for reporters).
type Finding struct {
	Kind      string  `json:"kind"`      // vuln, secret, eol, misconfig, license
	Path      string  `json:"path,omitempty"`
	Line      int     `json:"line,omitempty"`
	RuleID    string  `json:"rule_id,omitempty"`
	VulnID    string  `json:"vuln_id,omitempty"`
	Summary   string  `json:"summary"`
	Severity  string  `json:"severity"`   // LOW, MEDIUM, HIGH, CRITICAL
	CVSSScore *float64 `json:"cvss_score,omitempty"`
	Fixed     string  `json:"fixed,omitempty"`
	Source    string  `json:"source"`
	Package   string  `json:"package,omitempty"`
	Version   string  `json:"version,omitempty"`
}

// Result is the output of a scan run.
type Result struct {
	Target     string
	Findings   []Finding
	Packages   int
	StartedAt  string
	FinishedAt string
}

// ReporterMetadata describes a reporter plugin.
type ReporterMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`        // e.g., "jira-reporter"
	Version     string `json:"version"`     // plugin version
	Description string `json:"description"`
	Format      string `json:"format"`      // e.g., "json", "jira", "splunk"
	MimeType    string `json:"mime_type"`   // e.g., "application/json"
	Author      string `json:"author,omitempty"`
	Repository  string `json:"repository,omitempty"`
}

// ReporterConfig holds configuration for a reporter.
type ReporterConfig struct {
	Endpoint string                 `yaml:"endpoint"`   // API URL, webhook, file path
	Auth     map[string]string      `yaml:"auth,omitempty"`      // API keys, tokens
	Template string                 `yaml:"template,omitempty"`  // optional template path
	Custom   map[string]interface{} `yaml:"custom,omitempty"`    // provider-specific config
}

// Reporter is the interface for scan result reporters.
type Reporter interface {
	// Metadata returns plugin information.
	Metadata() ReporterMetadata

	// Validate checks if the configuration is valid.
	Validate(cfg ReporterConfig) error

	// Configure applies settings to the reporter.
	Configure(cfg ReporterConfig) error

	// Report generates a report and writes it to the writer.
	// May write to a file, HTTP endpoint, webhook, or other destination
	// depending on implementation.
	Report(result Result, w io.Writer) error

	// Close performs cleanup.
	Close() error
}
