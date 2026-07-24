// Package secret defines the Secret Rule SDK for Foxhole plugins.
// Secret rules detect hardcoded credentials in source code.
package secret

import (
	"regexp"
)

// Match represents a secret pattern match.
type Match struct {
	Start      int               // byte offset in content
	End        int               // byte offset in content
	Line       int               // line number (1-based)
	Column     int               // column number (1-based)
	Confidence float64           // 0.0 to 1.0
	Groups     map[string]string // named regex groups
}

// SecretRuleMetadata describes a secret detection rule.
type SecretRuleMetadata struct {
	ID          string `json:"id"`            // e.g., "aws-access-key"
	Name        string `json:"name"`          // human-readable name
	Version     string `json:"version"`       // plugin/rule version
	Description string `json:"description"`   // what this detects
	Severity    string `json:"severity"`      // LOW, MEDIUM, HIGH, CRITICAL
	Author      string `json:"author,omitempty"`
	Repository  string `json:"repository,omitempty"`
}

// SecretRule is the interface for secret detection plugins.
type SecretRule interface {
	// Metadata returns rule information.
	Metadata() SecretRuleMetadata

	// Pattern returns the compiled regex used for detection.
	// Callers may inspect this for performance tuning.
	Pattern() *regexp.Regexp

	// Match searches content for secret patterns.
	// Returns all matches found.
	Match(content []byte) []Match

	// IsEntropy-based rules may perform additional entropy checks.
	// Returns true if the match passes entropy validation (if applicable).
	Validate(match Match, context []byte) bool

	// Remediation returns guidance for fixing the finding.
	Remediation() string
}
