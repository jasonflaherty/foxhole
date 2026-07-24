package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiscoveredPackage is a package found on disk.
type DiscoveredPackage struct {
	Ecosystem string
	Name      string
	Version   string
	Path      string
	License   string // SPDX or declared license from manifest when known
}

// FilesystemScanner discovers dependencies from common lock/manifest files.
type FilesystemScanner struct{}

// NewFilesystemScanner creates a filesystem scanner.
func NewFilesystemScanner() *FilesystemScanner {
	return &FilesystemScanner{}
}

// ScanOptions controls package discovery behavior.
type ScanOptions struct {
	// DirectOnly skips lockfiles and uses manifests only (package.json / go.mod).
	DirectOnly bool
	// MaxPackages caps how many packages are returned (0 = unlimited).
	MaxPackages int
}

// Scan walks root and extracts packages from known manifests.
func (s *FilesystemScanner) Scan(root string) ([]DiscoveredPackage, error) {
	return s.ScanWithOptions(root, ScanOptions{})
}

// ScanWithOptions walks root with discovery limits for CI-scale targets.
func (s *FilesystemScanner) ScanWithOptions(root string, opts ScanOptions) ([]DiscoveredPackage, error) {
	var pkgs []DiscoveredPackage
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".foxhole" {
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		switch base {
		case "go.mod":
			found, err := parseGoMod(path)
			if err != nil {
				return err
			}
			pkgs = append(pkgs, found...)
		case "package.json":
			found, err := parsePackageJSON(path)
			if err != nil {
				return err
			}
			pkgs = append(pkgs, found...)
		case "package-lock.json":
			if opts.DirectOnly {
				return nil
			}
			found, err := parsePackageLock(path)
			if err != nil {
				return err
			}
			pkgs = append(pkgs, found...)
		case "requirements.txt":
			found, err := parseRequirements(path)
			if err != nil {
				return err
			}
			pkgs = append(pkgs, found...)
		case "Cargo.lock":
			if opts.DirectOnly {
				return nil
			}
			found, err := parseCargoLock(path)
			if err != nil {
				return err
			}
			pkgs = append(pkgs, found...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	pkgs = dedupe(pkgs)
	if opts.MaxPackages > 0 && len(pkgs) > opts.MaxPackages {
		pkgs = pkgs[:opts.MaxPackages]
	}
	return pkgs, nil
}

func parseGoMod(path string) ([]DiscoveredPackage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var pkgs []DiscoveredPackage
	inRequire := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.HasPrefix(line, "require (") {
			fields := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(fields) >= 2 {
				pkgs = append(pkgs, DiscoveredPackage{
					Ecosystem: "Go",
					Name:      fields[0],
					Version:   strings.TrimSuffix(fields[1], "//indirect"),
					Path:      path,
				})
			}
			continue
		}
		if inRequire {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ver := fields[1]
				if idx := strings.Index(ver, "//"); idx >= 0 {
					ver = strings.TrimSpace(ver[:idx])
				}
				pkgs = append(pkgs, DiscoveredPackage{
					Ecosystem: "Go",
					Name:      fields[0],
					Version:   ver,
					Path:      path,
				})
			}
		}
	}
	return pkgs, sc.Err()
}

func parsePackageJSON(path string) ([]DiscoveredPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		License         any               `json:"license"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}
	rootLicense := stringifyLicense(pkg.License)
	var out []DiscoveredPackage
	add := func(deps map[string]string) {
		for name, ver := range deps {
			out = append(out, DiscoveredPackage{
				Ecosystem: "npm",
				Name:      name,
				Version:   normalizeNPMVersion(ver),
				Path:      path,
			})
		}
	}
	add(pkg.Dependencies)
	add(pkg.DevDependencies)
	// Also record the root package license as a synthetic signal when present.
	if rootLicense != "" {
		out = append(out, DiscoveredPackage{
			Ecosystem: "npm",
			Name:      filepath.Base(filepath.Dir(path)),
			Version:   "",
			Path:      path,
			License:   rootLicense,
		})
	}
	return out, nil
}

func stringifyLicense(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]any:
		if typ, ok := t["type"].(string); ok {
			return strings.TrimSpace(typ)
		}
	}
	return ""
}

func normalizeNPMVersion(ver string) string {
	ver = strings.TrimSpace(ver)
	for _, p := range []string{">=", "<=", "^", "~", ">", "<", "="} {
		ver = strings.TrimPrefix(ver, p)
	}
	ver = strings.TrimSpace(ver)
	if ver == "" || strings.ContainsAny(ver, " |*") {
		return ""
	}
	return ver
}

func parsePackageLock(path string) ([]DiscoveredPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var pkgs []DiscoveredPackage
	for name, info := range lock.Packages {
		if name == "" || info.Version == "" {
			continue
		}
		n := strings.TrimPrefix(name, "node_modules/")
		if n == "" || strings.Contains(n, "node_modules/") {
			continue
		}
		pkgs = append(pkgs, DiscoveredPackage{Ecosystem: "npm", Name: n, Version: info.Version, Path: path})
	}
	if len(pkgs) == 0 {
		for name, info := range lock.Dependencies {
			pkgs = append(pkgs, DiscoveredPackage{Ecosystem: "npm", Name: name, Version: info.Version, Path: path})
		}
	}
	return pkgs, nil
}

func parseRequirements(path string) ([]DiscoveredPackage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var pkgs []DiscoveredPackage
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		name, ver := splitPyReq(line)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, DiscoveredPackage{Ecosystem: "PyPI", Name: name, Version: ver, Path: path})
	}
	return pkgs, sc.Err()
}

func splitPyReq(line string) (string, string) {
	for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
		if i := strings.Index(line, sep); i >= 0 {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):])
		}
	}
	return strings.TrimSpace(line), ""
}

func parseCargoLock(path string) ([]DiscoveredPackage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var pkgs []DiscoveredPackage
	var name, version string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[[package]]" {
			if name != "" && version != "" {
				pkgs = append(pkgs, DiscoveredPackage{Ecosystem: "crates.io", Name: name, Version: version, Path: path})
			}
			name, version = "", ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		}
		if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}
	if name != "" && version != "" {
		pkgs = append(pkgs, DiscoveredPackage{Ecosystem: "crates.io", Name: name, Version: version, Path: path})
	}
	return pkgs, sc.Err()
}

func dedupe(in []DiscoveredPackage) []DiscoveredPackage {
	seen := make(map[string]struct{}, len(in))
	out := make([]DiscoveredPackage, 0, len(in))
	for _, p := range in {
		key := fmt.Sprintf("%s|%s|%s", strings.ToLower(p.Ecosystem), strings.ToLower(p.Name), p.Version)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}
