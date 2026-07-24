package scan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
)

// EOLChecker matches discovered packages/runtimes against EOL data.
type EOLChecker struct {
	store *db.DB
	now   time.Time
}

// NewEOLChecker creates an EOL checker.
func NewEOLChecker(store *db.DB) *EOLChecker {
	return &EOLChecker{store: store, now: time.Now().UTC()}
}

var (
	goVersionRe   = regexp.MustCompile(`(?m)^go\s+(\d+\.\d+)`)
	nodeEnginesRe = regexp.MustCompile(`"node"\s*:\s*"([^"]+)"`)
)

// Check evaluates packages and common runtime pins for EOL.
func (c *EOLChecker) Check(ctx context.Context, root string, pkgs []DiscoveredPackage) ([]Finding, error) {
	var findings []Finding
	seen := map[string]struct{}{}

	add := func(f Finding) {
		key := f.Product + "|" + f.Cycle + "|" + f.Package.Name + "|" + f.Path
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		findings = append(findings, f)
	}

	for _, pkg := range pkgs {
		product, cycle := mapPackageToEOL(pkg)
		if product == "" || cycle == "" {
			continue
		}
		rec, err := c.store.MatchEOL(ctx, product, cycle)
		if err != nil {
			return nil, err
		}
		if rec == nil || !isEOL(rec.EOL, c.now) {
			continue
		}
		add(Finding{
			Kind:     KindEOL,
			Package:  pkg,
			Path:     pkg.Path,
			Product:  rec.Product,
			Cycle:    rec.Cycle,
			EOLDate:  rec.EOL,
			Summary:  product + " " + cycle + " reached end-of-life on " + rec.EOL,
			Severity: "high",
			Source:   "eol",
			Fixed:    rec.Latest,
		})
	}

	// Always inspect the scan root for runtime pins (even when no packages were discovered).
	roots := map[string]struct{}{root: {}}
	for _, pkg := range pkgs {
		if pkg.Path != "" {
			roots[filepath.Dir(pkg.Path)] = struct{}{}
		}
	}
	for dir := range roots {
		for _, f := range c.scanRuntimeFiles(ctx, dir) {
			add(f)
		}
	}
	return findings, nil
}

func (c *EOLChecker) scanRuntimeFiles(ctx context.Context, dir string) []Finding {
	var out []Finding
	checks := []struct {
		file    string
		product string
		extract func(string) string
	}{
		{"go.mod", "go", extractGoVersion},
		{"package.json", "nodejs", extractNodeEngine},
		{".python-version", "python", extractPythonVersionFile},
		{"runtime.txt", "python", extractPythonRuntimeTxt},
	}
	for _, ch := range checks {
		path := filepath.Join(dir, ch.file)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		cycle := ch.extract(string(data))
		if cycle == "" {
			continue
		}
		rec, err := c.store.MatchEOL(ctx, ch.product, cycle)
		if err != nil || rec == nil || !isEOL(rec.EOL, c.now) {
			continue
		}
		out = append(out, Finding{
			Kind:     KindEOL,
			Path:     path,
			Product:  rec.Product,
			Cycle:    rec.Cycle,
			EOLDate:  rec.EOL,
			Summary:  ch.product + " " + cycle + " reached end-of-life on " + rec.EOL,
			Severity: "high",
			Source:   "eol",
			Fixed:    rec.Latest,
		})
	}
	return out
}

func mapPackageToEOL(pkg DiscoveredPackage) (product, cycle string) {
	name := strings.ToLower(pkg.Name)
	ver := strings.TrimPrefix(pkg.Version, "v")
	switch {
	case pkg.Ecosystem == "PyPI" && (name == "django" || strings.HasSuffix(name, "/django")):
		return "django", majorMinor(ver)
	case name == "rails" || strings.HasSuffix(name, "/rails"):
		return "rails", majorMinor(ver)
	case name == "nginx":
		return "nginx", majorMinor(ver)
	}
	return "", ""
}

func majorMinor(ver string) string {
	ver = strings.TrimSpace(ver)
	parts := strings.Split(ver, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	if len(parts) == 1 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

func extractGoVersion(content string) string {
	m := goVersionRe.FindStringSubmatch(content)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func extractNodeEngine(content string) string {
	m := nodeEnginesRe.FindStringSubmatch(content)
	if len(m) < 2 {
		return ""
	}
	raw := m[1]
	// pick first X.Y-looking token
	re := regexp.MustCompile(`(\d+\.\d+)`)
	mm := re.FindStringSubmatch(raw)
	if len(mm) < 2 {
		// allow major-only like "16"
		re2 := regexp.MustCompile(`(\d+)`)
		mm = re2.FindStringSubmatch(raw)
		if len(mm) < 2 {
			return ""
		}
		return mm[1]
	}
	// nodejs EOL cycles are major-only
	return strings.Split(mm[1], ".")[0]
}

func extractPythonVersionFile(content string) string {
	line := strings.TrimSpace(strings.Split(content, "\n")[0])
	return majorMinor(line)
}

func extractPythonRuntimeTxt(content string) string {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "python-") {
			return majorMinor(strings.TrimPrefix(line, "python-"))
		}
	}
	return ""
}

func isEOL(eol string, now time.Time) bool {
	if eol == "" || strings.EqualFold(eol, "false") {
		return false
	}
	if strings.EqualFold(eol, "true") {
		return true
	}
	t, err := time.Parse("2006-01-02", eol)
	if err != nil {
		return false
	}
	return !t.After(now)
}
