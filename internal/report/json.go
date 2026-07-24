package report

import (
	"encoding/json"
	"io"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// JSON writes a machine-readable JSON report.
type JSON struct{}

// Format returns the format name.
func (JSON) Format() string { return "json" }

// Write encodes the result as JSON.
func (JSON) Write(w io.Writer, result *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
