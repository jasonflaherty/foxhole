package db

import (
	"context"
	"fmt"
)

// SecretRule is a regex-based secret detection rule.
type SecretRule struct {
	ID       string
	Name     string
	Pattern  string
	Severity string
	Enabled  bool
}

// EOLRecord is an end-of-life cycle for a product.
type EOLRecord struct {
	Product string
	Cycle   string
	EOL     string
	Latest  string
	Link    string
}

// ListSecretRules returns enabled secret rules.
func (d *DB) ListSecretRules(ctx context.Context) ([]SecretRule, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT id, name, pattern, severity, enabled FROM secret_rules WHERE enabled = 1
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SecretRule
	for rows.Next() {
		var r SecretRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Pattern, &r.Severity, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertSecretRule stores a secret rule.
func (d *DB) UpsertSecretRule(ctx context.Context, r SecretRule) error {
	enabled := 0
	if r.Enabled {
		enabled = 1
	}
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO secret_rules (id, name, pattern, severity, enabled)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			pattern = excluded.pattern,
			severity = excluded.severity,
			enabled = excluded.enabled
	`, r.ID, r.Name, r.Pattern, r.Severity, enabled)
	return err
}

// CountSecretRules returns how many rules are stored.
func (d *DB) CountSecretRules(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_rules`).Scan(&n)
	return n, err
}

// UpsertEOL stores an EOL cycle record.
func (d *DB) UpsertEOL(ctx context.Context, r EOLRecord) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO eol (product, cycle, eol, latest, link)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(product, cycle) DO UPDATE SET
			eol = excluded.eol,
			latest = excluded.latest,
			link = excluded.link
	`, r.Product, r.Cycle, r.EOL, r.Latest, r.Link)
	return err
}

// LookupEOL finds EOL rows for a product (case-insensitive).
func (d *DB) LookupEOL(ctx context.Context, product string) ([]EOLRecord, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT product, cycle, eol, latest, link FROM eol WHERE lower(product) = lower(?)
	`, product)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []EOLRecord
	for rows.Next() {
		var r EOLRecord
		if err := rows.Scan(&r.Product, &r.Cycle, &r.EOL, &r.Latest, &r.Link); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MatchEOL finds an EOL row for product+cycle (cycle matched as prefix or exact).
func (d *DB) MatchEOL(ctx context.Context, product, cycle string) (*EOLRecord, error) {
	rows, err := d.LookupEOL(ctx, product)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Cycle == cycle || (len(cycle) >= len(r.Cycle) && cycle[:len(r.Cycle)] == r.Cycle) {
			cp := r
			return &cp, nil
		}
		// also allow cycle "1.22" matching version "1.22.12"
		if len(r.Cycle) > 0 && len(cycle) > len(r.Cycle) && cycle[:len(r.Cycle)+1] == r.Cycle+"." {
			cp := r
			return &cp, nil
		}
	}
	return nil, nil
}

// CountEOL returns how many EOL rows are stored.
func (d *DB) CountEOL(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM eol`).Scan(&n)
	return n, err
}

// EnsurePhase2Seeds upserts built-in secret rules (so upgrades pick up new
// curated patterns) and loads EOL rows when that table is empty.
func (d *DB) EnsurePhase2Seeds(ctx context.Context, secrets []SecretRule, eols []EOLRecord) error {
	for _, r := range secrets {
		if err := d.UpsertSecretRule(ctx, r); err != nil {
			return fmt.Errorf("seed secret rule %s: %w", r.ID, err)
		}
	}
	n, err := d.CountEOL(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		for _, r := range eols {
			if err := d.UpsertEOL(ctx, r); err != nil {
				return fmt.Errorf("seed eol %s/%s: %w", r.Product, r.Cycle, err)
			}
		}
	}
	return nil
}
