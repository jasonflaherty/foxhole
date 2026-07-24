package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/db"
)

// ScanLicenses flags packages or LICENSE files matching high-risk license seeds.
func ScanLicenses(ctx context.Context, store *db.DB, root string, pkgs []DiscoveredPackage) ([]Finding, error) {
	risky, err := store.ListRiskyLicenses(ctx)
	if err != nil {
		return nil, err
	}
	if len(risky) == 0 {
		return nil, nil
	}
	riskSet := map[string]db.LicenseRecord{}
	for _, r := range risky {
		riskSet[strings.ToUpper(r.SPDX)] = r
		riskSet[strings.ToUpper(r.ID)] = r
		riskSet[strings.ToUpper(r.Name)] = r
	}

	var out []Finding
	// LICENSE file at root
	for _, name := range []string{"LICENSE", "LICENSE.md", "COPYING", "LICENCE"} {
		path := filepath.Join(root, name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(b)
		for key, rec := range riskSet {
			if key != "" && strings.Contains(strings.ToUpper(text), key) && rec.Risk == "high" {
				out = append(out, Finding{
					Kind:     KindLicense,
					Path:     path,
					RuleID:   "license-" + rec.ID,
					License:  firstNonEmpty(rec.SPDX, rec.ID),
					Summary:  "High-risk license detected in " + name + ": " + rec.Name,
					Severity: "medium",
					Source:   "licenses",
				})
				break
			}
		}
	}

	// Declared licenses on discovered packages (manifest metadata preferred).
	for _, pkg := range pkgs {
		declared := strings.ToUpper(strings.TrimSpace(pkg.License))
		if declared != "" {
			for key, rec := range riskSet {
				if key == "" || (rec.Risk != "high" && rec.Risk != "medium") {
					continue
				}
				if declared == key || strings.Contains(declared, key) {
					out = append(out, Finding{
						Kind:     KindLicense,
						Package:  pkg,
						Path:     pkg.Path,
						RuleID:   "license-declared-" + rec.ID,
						License:  firstNonEmpty(rec.SPDX, rec.ID, pkg.License),
						Summary:  "Declared package license " + pkg.License + " matches risk profile " + rec.Name,
						Severity: rec.Risk,
						Source:   "licenses",
					})
					break
				}
			}
			continue
		}
		cand := strings.ToUpper(pkg.Name)
		for key, rec := range riskSet {
			if key == "" || rec.Risk != "high" {
				continue
			}
			if strings.Contains(cand, "GPL") && strings.Contains(key, "GPL") {
				out = append(out, Finding{
					Kind:     KindLicense,
					Package:  pkg,
					RuleID:   "license-pkg-" + rec.ID,
					License:  firstNonEmpty(rec.SPDX, rec.ID),
					Summary:  "Package name suggests " + rec.Name + " — verify declared license",
					Severity: "low",
					Source:   "licenses",
				})
			}
		}
	}
	return out, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
