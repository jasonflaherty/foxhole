package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
)

const (
	providerID   = "osv"
	providerName = "OSV"
	apiQueryURL  = "https://api.osv.dev/v1/query"
)

// Store is the persistence surface required by the OSV provider.
type Store interface {
	UpsertPackage(ctx context.Context, p db.PackageRef) (int64, error)
	UpsertAdvisory(ctx context.Context, id, source, summary, severity, published, modified, aliasesJSON, rawJSON string) error
	UpsertCVE(ctx context.Context, id, source, summary, severity string, cvss *float64, published, modified, rawJSON string) error
	LinkPackageVuln(ctx context.Context, packageID int64, vulnID, vulnType, introduced, fixed string) error
	UpsertAlias(ctx context.Context, alias, vulnID string) error
	UpsertProvider(ctx context.Context, id, name, version, sha256sum, status string) error
	ProviderSHA256(ctx context.Context, id string) (string, bool, error)
	SearchPackageVulns(ctx context.Context, p db.PackageRef) ([]db.Finding, error)
	SetMetadata(ctx context.Context, key, value string) error
}

// HTTPDoer abstracts HTTP for tests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider implements provider.Provider for OSV.
type Provider struct {
	store          Store
	client         HTTPDoer
	packages       []provider.PackageQuery
	offline        bool
	lastHash       string
	seedAdvisories []seedAdvisory
}

type seedAdvisory struct {
	ID        string
	Ecosystem string
	Name      string
	Summary   string
	Severity  string
	Aliases   []string
	Fixed     string
}

// Option configures the OSV provider.
type Option func(*Provider)

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(c HTTPDoer) Option {
	return func(p *Provider) { p.client = c }
}

// WithPackages sets packages to refresh during Update (online mode).
func WithPackages(pkgs []provider.PackageQuery) Option {
	return func(p *Provider) { p.packages = pkgs }
}

// WithOffline disables network calls.
func WithOffline(offline bool) Option {
	return func(p *Provider) { p.offline = offline }
}

// WithSeedAdvisories injects fixture advisories (tests / offline bootstrap).
func WithSeedAdvisories(raw []byte) Option {
	return func(p *Provider) {
		var items []seedAdvisory
		if err := json.Unmarshal(raw, &items); err == nil {
			p.seedAdvisories = items
		}
	}
}

// New creates an OSV provider.
func New(store Store, opts ...Option) *Provider {
	p := &Provider{
		store:  store,
		client: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Metadata returns provider metadata.
func (p *Provider) Metadata() provider.Metadata {
	return provider.Metadata{
		ID:          providerID,
		Name:        providerName,
		Description: "Open Source Vulnerabilities database",
		Version:     "1",
	}
}

// Initialize prepares the provider.
func (p *Provider) Initialize(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Update refreshes OSV data for configured packages, or loads seed data.
func (p *Provider) Update(ctx context.Context) (*provider.UpdateResult, error) {
	var (
		count int
		hash  string
		err   error
	)

	if len(p.seedAdvisories) > 0 {
		count, hash, err = p.loadSeeds(ctx)
	} else if p.offline {
		return nil, fmt.Errorf("osv: offline update requires seed data or an existing database")
	} else if len(p.packages) == 0 {
		// No packages yet — record a successful empty sync so Verify can pass after seeds/scans.
		hash = db.SHA256Bytes([]byte("osv-empty"))
		if err := p.store.UpsertProvider(ctx, providerID, providerName, "1", hash, "ok"); err != nil {
			return nil, err
		}
		p.lastHash = hash
		return &provider.UpdateResult{Records: 0, ContentHash: hash, UpdatedAt: time.Now().UTC()}, nil
	} else {
		count, hash, err = p.fetchPackages(ctx, p.packages)
	}
	if err != nil {
		_ = p.store.UpsertProvider(ctx, providerID, providerName, "1", "", "error")
		return nil, err
	}

	if err := p.store.UpsertProvider(ctx, providerID, providerName, "1", hash, "ok"); err != nil {
		return nil, err
	}
	_ = p.store.SetMetadata(ctx, "osv_last_update", time.Now().UTC().Format(time.RFC3339))
	p.lastHash = hash
	return &provider.UpdateResult{Records: count, ContentHash: hash, UpdatedAt: time.Now().UTC()}, nil
}

// Verify checks stored content hash.
func (p *Provider) Verify(ctx context.Context) error {
	stored, ok, err := p.store.ProviderSHA256(ctx, providerID)
	if err != nil {
		return err
	}
	if !ok || stored == "" {
		return fmt.Errorf("osv: missing content hash; run foxhole db update")
	}
	if p.lastHash != "" && p.lastHash != stored {
		return fmt.Errorf("osv: content hash mismatch")
	}
	return nil
}

// Search queries the local database for OSV findings.
func (p *Provider) Search(ctx context.Context, q provider.PackageQuery) ([]provider.Result, error) {
	findings, err := p.store.SearchPackageVulns(ctx, db.PackageRef{
		Ecosystem: normalizeEcosystem(q.Ecosystem),
		Name:      q.Name,
		Version:   q.Version,
	})
	if err != nil {
		return nil, err
	}
	out := make([]provider.Result, 0, len(findings))
	for _, f := range findings {
		if f.Source != "" && f.Source != providerID && f.Source != "osv" {
			continue
		}
		var score *float64
		if f.CVSSScore.Valid {
			v := f.CVSSScore.Float64
			score = &v
		}
		out = append(out, provider.Result{
			ID:        f.VulnID,
			Summary:   f.Summary,
			Severity:  f.Severity,
			CVSSScore: score,
			Fixed:     f.Fixed,
			Source:    providerID,
		})
	}
	return out, nil
}

func (p *Provider) loadSeeds(ctx context.Context) (int, string, error) {
	raw, _ := json.Marshal(p.seedAdvisories)
	hash := db.SHA256Bytes(raw)
	count := 0
	for _, adv := range p.seedAdvisories {
		aliasesJSON, _ := json.Marshal(adv.Aliases)
		if err := p.store.UpsertAdvisory(ctx, adv.ID, providerID, adv.Summary, adv.Severity, "", "", string(aliasesJSON), ""); err != nil {
			return 0, "", err
		}
		for _, alias := range adv.Aliases {
			_ = p.store.UpsertAlias(ctx, alias, adv.ID)
			if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
				_ = p.store.UpsertCVE(ctx, strings.ToUpper(alias), providerID, adv.Summary, adv.Severity, nil, "", "", "")
			}
		}
		pkgID, err := p.store.UpsertPackage(ctx, db.PackageRef{
			Ecosystem: normalizeEcosystem(adv.Ecosystem),
			Name:      adv.Name,
			Version:   "",
		})
		if err != nil {
			return 0, "", err
		}
		vulnType := "advisory"
		if strings.HasPrefix(strings.ToUpper(adv.ID), "CVE-") {
			vulnType = "cve"
		}
		if err := p.store.LinkPackageVuln(ctx, pkgID, adv.ID, vulnType, "", adv.Fixed); err != nil {
			return 0, "", err
		}
		count++
	}
	return count, hash, nil
}

type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (p *Provider) fetchPackages(ctx context.Context, pkgs []provider.PackageQuery) (int, string, error) {
	var buf bytes.Buffer
	count := 0
	for _, pkg := range pkgs {
		vulns, raw, err := p.queryAPI(ctx, pkg)
		if err != nil {
			return 0, "", err
		}
		buf.Write(raw)
		for _, v := range vulns {
			if err := p.persistVuln(ctx, pkg, v); err != nil {
				return 0, "", err
			}
			count++
		}
	}
	return count, db.SHA256Bytes(buf.Bytes()), nil
}

func (p *Provider) queryAPI(ctx context.Context, pkg provider.PackageQuery) ([]osvVuln, []byte, error) {
	reqBody := osvQueryRequest{}
	reqBody.Package.Name = pkg.Name
	reqBody.Package.Ecosystem = osvEcosystem(pkg.Ecosystem)
	reqBody.Version = pkg.Version
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiQueryURL, bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("osv api: status %d: %s", resp.StatusCode, string(body))
	}
	var parsed osvQueryResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, err
	}
	return parsed.Vulns, body, nil
}

func (p *Provider) persistVuln(ctx context.Context, pkg provider.PackageQuery, v osvVuln) error {
	summary := v.Summary
	if summary == "" {
		summary = v.Details
	}
	severity := ""
	if len(v.Severity) > 0 {
		severity = v.Severity[0].Score
	}
	aliasesJSON, _ := json.Marshal(v.Aliases)
	raw, _ := json.Marshal(v)
	if err := p.store.UpsertAdvisory(ctx, v.ID, providerID, summary, severity, "", "", string(aliasesJSON), string(raw)); err != nil {
		return err
	}
	for _, alias := range v.Aliases {
		_ = p.store.UpsertAlias(ctx, alias, v.ID)
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			_ = p.store.UpsertCVE(ctx, strings.ToUpper(alias), providerID, summary, severity, nil, "", "", string(raw))
		}
	}
	fixed := ""
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					fixed = ev.Fixed
				}
			}
		}
	}
	pkgID, err := p.store.UpsertPackage(ctx, db.PackageRef{
		Ecosystem: normalizeEcosystem(pkg.Ecosystem),
		Name:      pkg.Name,
		Version:   "",
	})
	if err != nil {
		return err
	}
	vulnType := "advisory"
	if strings.HasPrefix(strings.ToUpper(v.ID), "CVE-") {
		vulnType = "cve"
	}
	if err := p.store.LinkPackageVuln(ctx, pkgID, v.ID, vulnType, "", fixed); err != nil {
		return fmt.Errorf("link %s -> pkg=%d type=%s: %w", v.ID, pkgID, vulnType, err)
	}
	return nil
}

func normalizeEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "go", "golang":
		return "Go"
	case "npm", "node":
		return "npm"
	case "pypi", "pip", "python":
		return "PyPI"
	case "crates.io", "cargo", "rust":
		return "crates.io"
	case "maven":
		return "Maven"
	case "rubygems", "gem":
		return "RubyGems"
	default:
		return eco
	}
}

func osvEcosystem(eco string) string {
	return normalizeEcosystem(eco)
}
