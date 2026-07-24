package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// SplitKindFiles maps finding kinds to output basenames (without extension).
var SplitKindFiles = []struct {
	Kind scan.Kind
	Base string
}{
	{scan.KindVuln, "foxhole-vulns"},
	{scan.KindSecret, "foxhole-secrets"},
	{scan.KindEOL, "foxhole-eol"},
	{scan.KindMisconfig, "foxhole-misconfig"},
	{scan.KindLicense, "foxhole-licenses"},
}

// WriteSplitJSON writes one JSON file per finding kind under outDir.
func WriteSplitJSON(result *scan.Result, outDir string, stdoutOut interface{ Write([]byte) (int, error) }) error {
	if outDir == "" {
		outDir = "."
	}
	for _, spec := range SplitKindFiles {
		filtered := &scan.Result{
			Target:     result.Target,
			StartedAt:  result.StartedAt,
			FinishedAt: result.FinishedAt,
			Packages:   result.Packages,
			Findings:   filterKind(result.Findings, spec.Kind),
		}
		path := filepath.Join(outDir, spec.Base+".json")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		err = (JSON{}).Write(f, filtered)
		_ = f.Close()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdoutOut, "wrote %s\n", path)
	}
	return nil
}

func filterKind(findings []scan.Finding, kind scan.Kind) []scan.Finding {
	out := make([]scan.Finding, 0)
	for _, f := range findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}
