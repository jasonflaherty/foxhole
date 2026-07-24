package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Console writes a human-readable scan report.
type Console struct {
	Out io.Writer
}

// Write prints findings to Out.
func (c Console) Write(result *scan.Result) error {
	w := c.Out
	fmt.Fprintf(w, "Foxhole scan: %s\n", result.Target)
	fmt.Fprintf(w, "Packages: %d  Findings: %d  Duration: %s\n",
		result.Packages, len(result.Findings), result.FinishedAt.Sub(result.StartedAt).Round(1e6))
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "No vulnerabilities found in local database.")
		return nil
	}
	fmt.Fprintln(w, strings.Repeat("-", 72))
	for _, f := range result.Findings {
		sev := f.Severity
		if sev == "" {
			sev = "UNKNOWN"
		}
		fmt.Fprintf(w, "[%s] %s\n", strings.ToUpper(sev), f.VulnID)
		fmt.Fprintf(w, "  package: %s@%s (%s)\n", f.Package.Name, f.Package.Version, f.Package.Ecosystem)
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

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
