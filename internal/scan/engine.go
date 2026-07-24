package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
)

// Finding is a scan result ready for reporting.
type Finding struct {
	Package   DiscoveredPackage
	VulnID    string
	Summary   string
	Severity  string
	CVSSScore *float64
	Fixed     string
	Source    string
}

// Result is the output of a scan run.
type Result struct {
	Target     string
	StartedAt  time.Time
	FinishedAt time.Time
	Packages   int
	Findings   []Finding
}

// Engine coordinates discovery and provider search.
type Engine struct {
	fs        *FilesystemScanner
	providers []provider.Provider
	store     *db.DB
}

// NewEngine creates a scan engine.
func NewEngine(store *db.DB, providers ...provider.Provider) *Engine {
	return &Engine{
		fs:        NewFilesystemScanner(),
		providers: providers,
		store:     store,
	}
}

// Scan scans a filesystem path for vulnerable dependencies.
func (e *Engine) Scan(ctx context.Context, target string) (*Result, error) {
	started := time.Now().UTC()
	pkgs, err := e.fs.Scan(target)
	if err != nil {
		return nil, fmt.Errorf("filesystem scan: %w", err)
	}

	var findings []Finding
	seen := map[string]struct{}{}
	for _, pkg := range pkgs {
		q := provider.PackageQuery{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
		}
		for _, p := range e.providers {
			results, err := p.Search(ctx, q)
			if err != nil {
				return nil, fmt.Errorf("%s search: %w", p.Metadata().ID, err)
			}
			for _, r := range results {
				key := pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version + "|" + r.ID
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, Finding{
					Package:   pkg,
					VulnID:    r.ID,
					Summary:   r.Summary,
					Severity:  r.Severity,
					CVSSScore: r.CVSSScore,
					Fixed:     r.Fixed,
					Source:    r.Source,
				})
			}
		}

		// Also query local DB directly for package links (covers seed/NVD-linked data).
		if e.store != nil {
			dbFindings, err := e.store.SearchPackageVulns(ctx, db.PackageRef{
				Ecosystem: pkg.Ecosystem,
				Name:      pkg.Name,
				Version:   pkg.Version,
			})
			if err != nil {
				return nil, err
			}
			for _, f := range dbFindings {
				key := pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version + "|" + f.VulnID
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				var score *float64
				if f.CVSSScore.Valid {
					v := f.CVSSScore.Float64
					score = &v
				}
				findings = append(findings, Finding{
					Package:   pkg,
					VulnID:    f.VulnID,
					Summary:   f.Summary,
					Severity:  f.Severity,
					CVSSScore: score,
					Fixed:     f.Fixed,
					Source:    f.Source,
				})
			}
		}
	}

	return &Result{
		Target:     target,
		StartedAt:  started,
		FinishedAt: time.Now().UTC(),
		Packages:   len(pkgs),
		Findings:   findings,
	}, nil
}
