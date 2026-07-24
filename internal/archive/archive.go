package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Write stores scan reports under archive/YYYY/MM/DD/ and returns the directory path.
func Write(baseDir string, result *scan.Result, when time.Time) (string, error) {
	if baseDir == "" {
		baseDir = "archive"
	}
	if when.IsZero() {
		when = time.Now().UTC()
	}
	dir := filepath.Join(baseDir, when.Format("2006"), when.Format("01"), when.Format("02"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	formats := []struct {
		name string
		file string
	}{
		{"json", "scan.json"},
		{"html", "scan.html"},
		{"markdown", "scan.md"},
		{"sarif", "scan.sarif"},
		{"console", "scan.txt"},
	}
	for _, f := range formats {
		w, err := report.ByName(f.name)
		if err != nil {
			return "", err
		}
		path := filepath.Join(dir, f.file)
		out, err := os.Create(path)
		if err != nil {
			return "", err
		}
		err = w.Write(out, result)
		_ = out.Close()
		if err != nil {
			return "", fmt.Errorf("write %s: %w", path, err)
		}
	}
	return dir, nil
}
