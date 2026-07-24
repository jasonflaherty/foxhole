package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Markdown writes a Markdown report.
type Markdown struct{}

// Format returns the format name.
func (Markdown) Format() string { return "markdown" }

// Write prints a Markdown document.
func (Markdown) Write(w io.Writer, result *scan.Result) error {
	fmt.Fprintf(w, "# Foxhole scan\n\n")
	fmt.Fprintf(w, "- **Target:** `%s`\n", result.Target)
	fmt.Fprintf(w, "- **Packages:** %d\n", result.Packages)
	fmt.Fprintf(w, "- **Findings:** %d\n", len(result.Findings))
	fmt.Fprintf(w, "- **Duration:** %s\n\n", result.FinishedAt.Sub(result.StartedAt).Round(1e6))
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}
	fmt.Fprintln(w, "| Severity | Kind | ID | Detail |")
	fmt.Fprintln(w, "|----------|------|----|--------|")
	for _, f := range result.Findings {
		detail := f.Summary
		if f.Kind == scan.KindSecret {
			detail = fmt.Sprintf("%s:%d — %s", f.Path, f.Line, f.Summary)
		}
		if f.Kind == scan.KindEOL {
			detail = fmt.Sprintf("%s@%s eol %s", f.Product, f.Cycle, f.EOLDate)
		}
		if f.Package.Name != "" && f.Kind == scan.KindVuln {
			detail = fmt.Sprintf("%s@%s — %s", f.Package.Name, f.Package.Version, f.Summary)
		}
		detail = strings.ReplaceAll(detail, "|", "\\|")
		detail = strings.ReplaceAll(detail, "\n", " ")
		fmt.Fprintf(w, "| %s | %s | `%s` | %s |\n",
			severityOrUnknown(f.Severity), f.Kind, f.ID(), truncate(detail, 160))
	}
	return nil
}
