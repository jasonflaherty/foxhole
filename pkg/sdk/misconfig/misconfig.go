// Package misconfig defines the Misconfiguration Rule SDK for Foxhole plugins.
// Misconfig rules detect security issues in infrastructure-as-code and config files.
package misconfig

import (
	"context"
)

// Violation represents a misconfiguration finding.
type Violation struct {
	ID          string // e.g., "docker-run-as-root"
	Line        int    // line number in file (1-based)
	Column      int    // column number (1-based)
	Severity    string // LOW, MEDIUM, HIGH, CRITICAL
	Summary     string // brief description
	Description string // detailed explanation
	Fix         string // suggested remediation
}

// MisconfigRuleMetadata describes a misconfiguration rule.
type MisconfigRuleMetadata struct {
	ID             string `json:"id"`
	Name           string `json:"name"`          // human-readable name
	Version        string `json:"version"`       // plugin/rule version
	Description    string `json:"description"`
	ResourceType   string `json:"resource_type"` // "dockerfile", "k8s", "terraform", etc.
	CISBenchmark   string `json:"cis_benchmark,omitempty"`   // e.g., "CIS Docker 1.0"
	Author         string `json:"author,omitempty"`
	Repository     string `json:"repository,omitempty"`
}

// ResourceContext provides parsed data for rule checking.
type ResourceContext struct {
	Path     string                 // filesystem path
	Type     string                 // resource type (dockerfile, k8s, etc.)
	Content  []byte                 // raw file content
	Parsed   interface{}            // parsed (e.g., *dockerfile.Dockerfile, K8s object)
	Metadata map[string]interface{} // additional context
}

// MisconfigRule is the interface for misconfiguration detection plugins.
type MisconfigRule interface {
	// Metadata returns rule information.
	Metadata() MisconfigRuleMetadata

	// Check evaluates a resource and returns any violations.
	Check(ctx context.Context, resource ResourceContext) []Violation

	// Examples returns sample resources for documentation.
	// Maps resource names to example content or structures.
	Examples() map[string]interface{}

	// SupportsResourceType returns true if this rule applies to the resource type.
	SupportsResourceType(resourceType string) bool
}
