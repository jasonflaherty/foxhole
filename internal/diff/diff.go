package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Fingerprint uniquely identifies a finding across scans.
func Fingerprint(f scan.Finding) string {
	return strings.Join([]string{
		string(f.Kind),
		f.ID(),
		f.Package.Ecosystem,
		f.Package.Name,
		f.Package.Version,
		f.Path,
		fmt.Sprintf("%d", f.Line),
		f.Product,
		f.Cycle,
	}, "|")
}

// SetFromJSON loads fingerprints from a findings JSON array.
func SetFromJSON(raw string) (map[string]scan.Finding, error) {
	var findings []scan.Finding
	if raw == "" {
		raw = "[]"
	}
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		return nil, err
	}
	out := make(map[string]scan.Finding, len(findings))
	for _, f := range findings {
		out[Fingerprint(f)] = f
	}
	return out, nil
}

// SnapshotJSON marshals findings for history storage.
func SnapshotJSON(findings []scan.Finding) (string, error) {
	b, err := json.Marshal(findings)
	if err != nil {
		return "[]", err
	}
	return string(b), nil
}

// Result is a diff between two scans.
type Result struct {
	Added   []scan.Finding
	Removed []scan.Finding
	Kept    int
}

// Compare computes added/removed findings.
func Compare(previous, latest map[string]scan.Finding) Result {
	var r Result
	for k, f := range latest {
		if _, ok := previous[k]; !ok {
			r.Added = append(r.Added, f)
		} else {
			r.Kept++
		}
	}
	for k, f := range previous {
		if _, ok := latest[k]; !ok {
			r.Removed = append(r.Removed, f)
		}
	}
	sort.Slice(r.Added, func(i, j int) bool { return r.Added[i].ID() < r.Added[j].ID() })
	sort.Slice(r.Removed, func(i, j int) bool { return r.Removed[i].ID() < r.Removed[j].ID() })
	return r
}

// Write prints a human-readable diff.
func Write(w io.Writer, r Result) {
	fmt.Fprintf(w, "Diff: +%d / -%d (unchanged %d)\n", len(r.Added), len(r.Removed), r.Kept)
	if len(r.Added) > 0 {
		fmt.Fprintln(w, "\nAdded:")
		for _, f := range r.Added {
			fmt.Fprintf(w, "  + [%s] %s (%s) %s\n", strings.ToUpper(f.Severity), f.ID(), f.Kind, f.Summary)
		}
	}
	if len(r.Removed) > 0 {
		fmt.Fprintln(w, "\nRemoved:")
		for _, f := range r.Removed {
			fmt.Fprintf(w, "  - [%s] %s (%s) %s\n", strings.ToUpper(f.Severity), f.ID(), f.Kind, f.Summary)
		}
	}
	if len(r.Added) == 0 && len(r.Removed) == 0 {
		fmt.Fprintln(w, "No changes between scans.")
	}
}
