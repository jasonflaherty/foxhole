package report

import (
	"encoding/json"
	"io"

	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/version"
)

// SchemaVersion is the stable JSON export schema for CI/SOAR parsers.
const SchemaVersion = "1.0.0"

// Envelope wraps a scan result for machine consumers.
type Envelope struct {
	SchemaVersion string       `json:"schema_version"`
	Tool          string       `json:"tool"`
	ToolVersion   string       `json:"tool_version"`
	Result        *scan.Result `json:"result"`
}

// WrapResult builds a versioned export envelope.
func WrapResult(result *scan.Result) Envelope {
	return Envelope{
		SchemaVersion: SchemaVersion,
		Tool:          "foxhole",
		ToolVersion:   version.Version,
		Result:        result,
	}
}

// JSON writes a machine-readable JSON report with schema envelope.
type JSON struct{}

// Format returns the format name.
func (JSON) Format() string { return "json" }

// Write encodes the result as a versioned JSON envelope.
func (JSON) Write(w io.Writer, result *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(WrapResult(result))
}
