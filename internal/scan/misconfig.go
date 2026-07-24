package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ScanDockerfileMisconfig applies lightweight Dockerfile hardening checks.
func ScanDockerfileMisconfig(root string) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		name := strings.ToLower(d.Name())
		if name != "dockerfile" && !strings.HasPrefix(name, "dockerfile.") {
			return nil
		}
		findings, err := checkDockerfile(path)
		if err != nil {
			return nil
		}
		out = append(out, findings...)
		return nil
	})
	return out, err
}

func checkDockerfile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var (
		out        []Finding
		hasUser    bool
		lineNum    int
		fromLatest bool
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "USER ") {
			hasUser = true
			user := strings.TrimSpace(line[5:])
			if user == "root" || user == "0" {
				out = append(out, Finding{
					Kind:     KindMisconfig,
					Path:     path,
					Line:     lineNum,
					RuleID:   "dockerfile-user-root",
					Summary:  "Dockerfile runs as root USER",
					Severity: "medium",
					Source:   "misconfig",
				})
			}
		}
		if strings.HasPrefix(upper, "FROM ") {
			from := strings.TrimSpace(line[5:])
			if strings.HasSuffix(from, ":latest") || (!strings.Contains(from, ":") && !strings.Contains(from, "@")) {
				fromLatest = true
				out = append(out, Finding{
					Kind:     KindMisconfig,
					Path:     path,
					Line:     lineNum,
					RuleID:   "dockerfile-from-latest",
					Summary:  "Dockerfile FROM uses unpinned/latest tag",
					Severity: "low",
					Source:   "misconfig",
				})
			}
		}
		if strings.Contains(upper, "CURL ") && strings.Contains(upper, "|") && strings.Contains(upper, "SH") {
			out = append(out, Finding{
				Kind:     KindMisconfig,
				Path:     path,
				Line:     lineNum,
				RuleID:   "dockerfile-curl-pipe-sh",
				Summary:  "Dockerfile pipes remote script into a shell",
				Severity: "high",
				Source:   "misconfig",
			})
		}
	}
	_ = fromLatest
	if !hasUser {
		out = append(out, Finding{
			Kind:     KindMisconfig,
			Path:     path,
			Line:     1,
			RuleID:   "dockerfile-missing-user",
			Summary:  "Dockerfile does not set a non-root USER",
			Severity: "medium",
			Source:   "misconfig",
		})
	}
	return out, sc.Err()
}
