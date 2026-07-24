package db

import (
	"context"
	"database/sql"
)

// LicenseRecord is a known license risk entry.
type LicenseRecord struct {
	ID   string
	Name string
	SPDX string
	Risk string
}

// UpsertKEV inserts or updates a KEV entry.
func (d *DB) UpsertKEV(ctx context.Context, cveID, vendor, product, dateAdded, dueDate, ransomware string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO kev (cve_id, vendor_project, product, date_added, due_date, known_ransomware)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			vendor_project = excluded.vendor_project,
			product = excluded.product,
			date_added = excluded.date_added,
			due_date = excluded.due_date,
			known_ransomware = excluded.known_ransomware
	`, cveID, vendor, product, dateAdded, dueDate, ransomware)
	return err
}

// InKEV reports whether a CVE is listed in KEV.
func (d *DB) InKEV(ctx context.Context, cveID string) (bool, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(1) FROM kev WHERE cve_id = ?`, stringsToUpperCVE(cveID)).Scan(&n)
	return n > 0, err
}

// UpsertEPSS stores an EPSS score.
func (d *DB) UpsertEPSS(ctx context.Context, cveID string, score, percentile float64) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO epss (cve_id, score, percentile, updated_at)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(cve_id) DO UPDATE SET
			score = excluded.score,
			percentile = excluded.percentile,
			updated_at = excluded.updated_at
	`, stringsToUpperCVE(cveID), score, percentile)
	return err
}

// EPSSScore returns the EPSS score when present.
func (d *DB) EPSSScore(ctx context.Context, cveID string) (float64, bool, error) {
	var score float64
	err := d.sql.QueryRowContext(ctx, `SELECT score FROM epss WHERE cve_id = ?`, stringsToUpperCVE(cveID)).Scan(&score)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return score, true, nil
}

// UpsertLicense stores a license risk record.
func (d *DB) UpsertLicense(ctx context.Context, id, name, spdx, risk string, osi bool) error {
	osiInt := 0
	if osi {
		osiInt = 1
	}
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO licenses (id, name, spdx_id, risk, osi_approved)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			spdx_id = excluded.spdx_id,
			risk = excluded.risk,
			osi_approved = excluded.osi_approved
	`, id, name, spdx, risk, osiInt)
	return err
}

// ListRiskyLicenses returns licenses marked medium/high risk.
func (d *DB) ListRiskyLicenses(ctx context.Context) ([]LicenseRecord, error) {
	rows, err := d.sql.QueryContext(ctx, `
		SELECT id, name, spdx_id, risk FROM licenses WHERE risk IN ('high', 'medium')
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []LicenseRecord
	for rows.Next() {
		var r LicenseRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.SPDX, &r.Risk); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResolveCVEAlias maps an advisory id to a CVE via aliases table.
func (d *DB) ResolveCVEAlias(ctx context.Context, id string) (string, error) {
	var cve string
	err := d.sql.QueryRowContext(ctx, `
		SELECT alias FROM aliases WHERE vuln_id = ? AND alias LIKE 'CVE-%'
		UNION
		SELECT vuln_id FROM aliases WHERE alias = ? AND vuln_id LIKE 'CVE-%'
		LIMIT 1
	`, id, id).Scan(&cve)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return cve, err
}

func stringsToUpperCVE(s string) string {
	if len(s) >= 4 && (s[0] == 'c' || s[0] == 'C') {
		b := make([]byte, len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			b[i] = c
		}
		return string(b)
	}
	return s
}
