package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Writer renders a scan result.
type Writer interface {
	Format() string
	Write(w io.Writer, result *scan.Result) error
}

// ByName returns a reporter for a format name.
func ByName(name string) (Writer, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "console", "text":
		return Console{}, nil
	case "json":
		return JSON{}, nil
	case "markdown", "md":
		return Markdown{}, nil
	case "html":
		return HTML{}, nil
	case "sarif":
		return SARIF{}, nil
	case "junit", "xml":
		return JUnit{}, nil
	case "cyclonedx", "cdx":
		return CycloneDX{}, nil
	case "spdx":
		return SPDX{}, nil
	default:
		return nil, fmt.Errorf("unknown report format %q", name)
	}
}

// ParseFormats splits a comma-separated report list.
func ParseFormats(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return []string{"console"}
	}
	return out
}

// WriteAll writes each requested format. Console goes to stdoutOut; file formats
// are written under outDir as foxhole-report.<ext>.
func WriteAll(formats []string, result *scan.Result, stdoutOut io.Writer, outDir string) error {
	if outDir == "" {
		outDir = "."
	}
	for _, name := range formats {
		w, err := ByName(name)
		if err != nil {
			return err
		}
		if name == "console" || name == "text" {
			if err := w.Write(stdoutOut, result); err != nil {
				return err
			}
			continue
		}
		ext := name
		if name == "markdown" || name == "md" {
			ext = "md"
		}
		if name == "junit" || name == "xml" {
			ext = "junit.xml"
		}
		if name == "cyclonedx" || name == "cdx" {
			ext = "cdx.json"
		}
		if name == "spdx" {
			ext = "spdx.json"
		}
		path := filepath.Join(outDir, "foxhole-report."+ext)
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		err = w.Write(f, result)
		_ = f.Close()
		if err != nil {
			return err
		}
		fmt.Fprintf(stdoutOut, "wrote %s\n", path)
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

func severityOrUnknown(s string) string {
	if s == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(s)
}
