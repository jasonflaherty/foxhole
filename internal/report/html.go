package report

import (
	"fmt"
	"html"
	"io"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// HTML writes a simple HTML report.
type HTML struct{}

// Format returns the format name.
func (HTML) Format() string { return "html" }

// Write prints an HTML document.
func (HTML) Write(w io.Writer, result *scan.Result) error {
	fmt.Fprintln(w, "<!DOCTYPE html>")
	fmt.Fprintln(w, `<html lang="en"><head><meta charset="utf-8"><title>Foxhole scan</title>`)
	fmt.Fprintln(w, `<style>
body{font-family:ui-sans-serif,system-ui,sans-serif;margin:2rem;background:#0f1419;color:#e7ecf3}
h1{font-size:1.5rem} .meta{opacity:.8;margin-bottom:1.5rem}
table{border-collapse:collapse;width:100%} th,td{border:1px solid #2a3441;padding:.5rem .75rem;text-align:left;vertical-align:top}
th{background:#1a222d} .sev{font-weight:600} .high,.critical{color:#ff7b72} .medium{color:#e3b341} .low{color:#7ee787}
</style></head><body>`)
	fmt.Fprintf(w, "<h1>Foxhole scan</h1>\n")
	fmt.Fprintf(w, `<div class="meta">Target: <code>%s</code> · Packages: %d · Findings: %d · Duration: %s</div>`+"\n",
		html.EscapeString(result.Target), result.Packages, len(result.Findings),
		result.FinishedAt.Sub(result.StartedAt).Round(1e6))
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "<p>No findings.</p></body></html>")
		return nil
	}
	fmt.Fprintln(w, "<table><thead><tr><th>Severity</th><th>Kind</th><th>ID</th><th>Detail</th></tr></thead><tbody>")
	for _, f := range result.Findings {
		sev := severityOrUnknown(f.Severity)
		cls := stringsToClass(sev)
		detail := f.Summary
		if f.Kind == scan.KindSecret {
			detail = fmt.Sprintf("%s:%d — %s", f.Path, f.Line, f.Summary)
		}
		if f.Kind == scan.KindEOL {
			detail = fmt.Sprintf("%s@%s eol %s", f.Product, f.Cycle, f.EOLDate)
		}
		if f.Kind == scan.KindVuln && f.Package.Name != "" {
			detail = fmt.Sprintf("%s@%s (%s) — %s", f.Package.Name, f.Package.Version, f.Package.Ecosystem, f.Summary)
		}
		fmt.Fprintf(w, `<tr><td class="sev %s">%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>`+"\n",
			cls, html.EscapeString(sev), html.EscapeString(string(f.Kind)),
			html.EscapeString(f.ID()), html.EscapeString(detail))
	}
	fmt.Fprintln(w, "</tbody></table></body></html>")
	return nil
}

func stringsToClass(sev string) string {
	switch sev {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return ""
	}
}
