package ghsa

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/pkg/provider"
)

const providerID = "ghsa"

// Store searches advisories for GHSA IDs.
type Store interface {
	SQL() *sql.DB
}

// Provider surfaces GitHub Security Advisory IDs already stored (via OSV aliases).
type Provider struct {
	store Store
}

func New(store Store) *Provider { return &Provider{store: store} }

func (p *Provider) Metadata() provider.Metadata {
	return provider.Metadata{ID: providerID, Name: "GHSA", Description: "GitHub Security Advisories (from local advisory store)", Version: "1"}
}
func (p *Provider) Initialize(context.Context) error { return nil }
func (p *Provider) Verify(context.Context) error     { return nil }

func (p *Provider) Update(ctx context.Context) (*provider.UpdateResult, error) {
	var n int
	err := p.store.SQL().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM advisories WHERE id LIKE 'GHSA-%' OR source = 'ghsa'
	`).Scan(&n)
	if err != nil {
		return nil, err
	}
	return &provider.UpdateResult{Records: n, ContentHash: fmt.Sprintf("ghsa-count-%d", n), UpdatedAt: time.Now().UTC()}, nil
}

func (p *Provider) Search(ctx context.Context, q provider.PackageQuery) ([]provider.Result, error) {
	rows, err := p.store.SQL().QueryContext(ctx, `
		SELECT a.id, a.summary, a.severity, a.source
		FROM advisories a
		JOIN package_vulns pv ON pv.vuln_id = a.id AND pv.vuln_type = 'advisory'
		JOIN packages p ON p.id = pv.package_id
		WHERE p.ecosystem = ? AND p.name = ? AND (p.version = ? OR p.version = '')
		  AND (a.id LIKE 'GHSA-%' OR a.source = 'ghsa' OR a.source = 'osv')
	`, q.Ecosystem, q.Name, q.Version)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []provider.Result
	for rows.Next() {
		var r provider.Result
		if err := rows.Scan(&r.ID, &r.Summary, &r.Severity, &r.Source); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(r.ID, "GHSA-") && r.Source != "ghsa" {
			continue
		}
		r.Source = providerID
		out = append(out, r)
	}
	return out, rows.Err()
}
