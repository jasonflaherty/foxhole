package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Console writes a human-readable scan report.
type Console struct{}

// Format returns the format name.
func (Console) Format() string { return "console" }

// Write prints findings to w.
func (Console) Write(w io.Writer, result *scan.Result) error {
	fmt.Fprintf(w, "Foxhole scan: %s\n", result.Target)
	fmt.Fprintf(w, "Packages: %d  Findings: %d  Duration: %s\n",
		result.Packages, len(result.Findings), result.FinishedAt.Sub(result.StartedAt).Round(1e6))
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}
	fmt.Fprintln(w, strings.Repeat("-", 72))
	for _, f := range result.Findings {
		fmt.Fprintf(w, "[%s] %s (%s)\n", severityOrUnknown(f.Severity), f.ID(), f.Kind)
		switch f.Kind {
		case scan.KindSecret:
			fmt.Fprintf(w, "  path:    %s:%d\n", f.Path, f.Line)
		case scan.KindEOL:
			fmt.Fprintf(w, "  product: %s@%s eol=%s\n", f.Product, f.Cycle, f.EOLDate)
			if f.Package.Name != "" {
				fmt.Fprintf(w, "  package: %s@%s (%s)\n", f.Package.Name, f.Package.Version, f.Package.Ecosystem)
			}
		default:
			if f.Package.Name != "" {
				fmt.Fprintf(w, "  package: %s@%s (%s)\n", f.Package.Name, f.Package.Version, f.Package.Ecosystem)
			}
		}
		if f.Summary != "" {
			fmt.Fprintf(w, "  summary: %s\n", truncate(f.Summary, 120))
		}
		if f.Fixed != "" {
			fmt.Fprintf(w, "  fixed:   %s\n", f.Fixed)
		}
		if f.Source != "" {
			fmt.Fprintf(w, "  source:  %s\n", f.Source)
		}
		fmt.Fprintln(w)
	}
	return nil
}
