package scan

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
)

// Kind classifies a finding.
type Kind string

const (
	KindVuln   Kind = "vuln"
	KindSecret Kind = "secret"
	KindEOL    Kind = "eol"
)

// Finding is a scan result ready for reporting.
type Finding struct {
	Kind      Kind              `json:"kind"`
	Package   DiscoveredPackage `json:"package,omitempty"`
	Path      string            `json:"path,omitempty"`
	Line      int               `json:"line,omitempty"`
	RuleID    string            `json:"rule_id,omitempty"`
	VulnID    string            `json:"vuln_id,omitempty"`
	Summary   string            `json:"summary"`
	Severity  string            `json:"severity"`
	CVSSScore *float64          `json:"cvss_score,omitempty"`
	Fixed     string            `json:"fixed,omitempty"`
	Source    string            `json:"source"`
	Product   string            `json:"product,omitempty"`
	Cycle     string            `json:"cycle,omitempty"`
	EOLDate   string            `json:"eol_date,omitempty"`
}

// ID returns a stable identifier for display/dedupe.
func (f Finding) ID() string {
	switch f.Kind {
	case KindSecret:
		if f.RuleID != "" {
			return f.RuleID
		}
	case KindEOL:
		if f.Product != "" {
			return f.Product + "@" + f.Cycle
		}
	}
	if f.VulnID != "" {
		return f.VulnID
	}
	return f.RuleID
}

// Result is the output of a scan run.
type Result struct {
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Packages   int       `json:"packages"`
	Findings   []Finding `json:"findings"`
}

// EngineOptions configures optional scanners.
type EngineOptions struct {
	Secrets bool
	EOL     bool
}

// Engine coordinates discovery and provider search.
type Engine struct {
	fs        *FilesystemScanner
	providers []provider.Provider
	store     *db.DB
	opts      EngineOptions
}

// NewEngine creates a scan engine with secrets and EOL enabled by default.
func NewEngine(store *db.DB, providers ...provider.Provider) *Engine {
	return &Engine{
		fs:        NewFilesystemScanner(),
		providers: providers,
		store:     store,
		opts:      EngineOptions{Secrets: true, EOL: true},
	}
}

// WithOptions sets scanner toggles.
func (e *Engine) WithOptions(opts EngineOptions) *Engine {
	e.opts = opts
	return e
}

// Scan scans a filesystem path for vulns, secrets, and EOL issues.
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
				key := "vuln|" + pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version + "|" + r.ID
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, Finding{
					Kind:      KindVuln,
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
				key := "vuln|" + pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version + "|" + f.VulnID
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
					Kind:      KindVuln,
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

	if e.opts.Secrets && e.store != nil {
		secretFindings, err := NewSecretsScanner(e.store).Scan(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("secret scan: %w", err)
		}
		for _, f := range secretFindings {
			key := "secret|" + f.Path + "|" + f.RuleID + "|" + strconv.Itoa(f.Line)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}

	if e.opts.EOL && e.store != nil {
		eolFindings, err := NewEOLChecker(e.store).Check(ctx, target, pkgs)
		if err != nil {
			return nil, fmt.Errorf("eol check: %w", err)
		}
		for _, f := range eolFindings {
			key := "eol|" + f.Product + "|" + f.Cycle + "|" + f.Package.Name + "|" + f.Path
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, f)
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
