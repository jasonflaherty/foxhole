package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// PackageRef identifies a software package.
type PackageRef struct {
	Ecosystem string
	Name      string
	Version   string
}

// Finding is a vulnerability matched to a package.
type Finding struct {
	Package   PackageRef
	VulnID    string
	VulnType  string
	Summary   string
	Severity  string
	CVSSScore sql.NullFloat64
	Fixed     string
	Source    string
}

// UpsertPackage inserts or returns an existing package row id.
func (d *DB) UpsertPackage(ctx context.Context, p PackageRef) (int64, error) {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO packages (ecosystem, name, version)
		VALUES (?, ?, ?)
		ON CONFLICT(ecosystem, name, version) DO UPDATE SET name = excluded.name
	`, p.Ecosystem, p.Name, p.Version)
	if err != nil {
		return 0, err
	}
	// Always SELECT the real packages.id. SQLite LastInsertId after ON CONFLICT DO UPDATE
	// can return a stale rowid from a prior INSERT (e.g. advisories), which breaks FKs.
	var id int64
	err = d.sql.QueryRowContext(ctx, `
		SELECT id FROM packages WHERE ecosystem = ? AND name = ? AND version = ?
	`, p.Ecosystem, p.Name, p.Version).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("resolve package id: %w", err)
	}
	return id, nil
}

// UpsertCVE stores a CVE record.
func (d *DB) UpsertCVE(ctx context.Context, id, source, summary, severity string, cvss *float64, published, modified, rawJSON string) error {
	var score any
	if cvss != nil {
		score = *cvss
	}
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO cves (id, source, summary, severity, cvss_score, published, modified, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			source = excluded.source,
			summary = excluded.summary,
			severity = excluded.severity,
			cvss_score = excluded.cvss_score,
			published = excluded.published,
			modified = excluded.modified,
			raw_json = excluded.raw_json
	`, id, source, summary, severity, score, published, modified, rawJSON)
	return err
}

// UpsertAdvisory stores an advisory record.
func (d *DB) UpsertAdvisory(ctx context.Context, id, source, summary, severity, published, modified, aliasesJSON, rawJSON string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO advisories (id, source, summary, severity, published, modified, aliases, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			source = excluded.source,
			summary = excluded.summary,
			severity = excluded.severity,
			published = excluded.published,
			modified = excluded.modified,
			aliases = excluded.aliases,
			raw_json = excluded.raw_json
	`, id, source, summary, severity, published, modified, aliasesJSON, rawJSON)
	return err
}

// LinkPackageVuln associates a package with a vulnerability.
func (d *DB) LinkPackageVuln(ctx context.Context, packageID int64, vulnID, vulnType, introduced, fixed string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO package_vulns (package_id, vuln_id, vuln_type, introduced, fixed)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(package_id, vuln_id, vuln_type) DO UPDATE SET
			introduced = excluded.introduced,
			fixed = excluded.fixed
	`, packageID, vulnID, vulnType, introduced, fixed)
	return err
}

// UpsertAlias stores a vulnerability alias mapping.
func (d *DB) UpsertAlias(ctx context.Context, alias, vulnID string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT OR IGNORE INTO aliases (alias, vuln_id) VALUES (?, ?)
	`, alias, vulnID)
	return err
}

// SearchPackageVulns finds vulnerabilities for a package by ecosystem and name.
// Version matching is best-effort: exact package version rows plus name-only rows.
func (d *DB) SearchPackageVulns(ctx context.Context, p PackageRef) ([]Finding, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT p.ecosystem, p.name, p.version, pv.vuln_id, pv.vuln_type, pv.fixed,
			COALESCE(c.summary, a.summary, '') AS summary,
			COALESCE(c.severity, a.severity, '') AS severity,
			c.cvss_score,
			COALESCE(c.source, a.source, '') AS source
		FROM packages p
		JOIN package_vulns pv ON pv.package_id = p.id
		LEFT JOIN cves c ON pv.vuln_type = 'cve' AND c.id = pv.vuln_id
		LEFT JOIN advisories a ON pv.vuln_type = 'advisory' AND a.id = pv.vuln_id
		WHERE lower(p.ecosystem) = lower(?) AND lower(p.name) = lower(?)
		  AND (p.version = '' OR p.version = ? OR ? = '')
	`, p.Ecosystem, p.Name, p.Version, p.Version)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(
			&f.Package.Ecosystem,
			&f.Package.Name,
			&f.Package.Version,
			&f.VulnID,
			&f.VulnType,
			&f.Fixed,
			&f.Summary,
			&f.Severity,
			&f.CVSSScore,
			&f.Source,
		); err != nil {
			return nil, err
		}
		if f.Package.Version == "" {
			f.Package.Version = p.Version
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SearchCVE returns a CVE by id.
func (d *DB) SearchCVE(ctx context.Context, id string) (*Finding, error) {
	var f Finding
	err := d.sql.QueryRowContext(ctx, `
		SELECT id, 'cve', summary, severity, cvss_score, source
		FROM cves WHERE id = ? OR id = ?
	`, id, strings.ToUpper(id)).Scan(&f.VulnID, &f.VulnType, &f.Summary, &f.Severity, &f.CVSSScore, &f.Source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// CountVulns returns approximate vulnerability inventory size.
func (d *DB) CountVulns(ctx context.Context) (cves, advisories int, err error) {
	err = d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM cves`).Scan(&cves)
	if err != nil {
		return 0, 0, err
	}
	err = d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM advisories`).Scan(&advisories)
	if err != nil {
		return 0, 0, fmt.Errorf("count advisories: %w", err)
	}
	return cves, advisories, nil
}
