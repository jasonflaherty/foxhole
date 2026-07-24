package db

import (
	"context"
	"database/sql"
	"time"
)

// ScanRecord is a persisted scan run.
type ScanRecord struct {
	ID           int64     `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at,omitempty"`
	Target       string    `json:"target"`
	FindingCount int       `json:"finding_count"`
	Status       string    `json:"status"`
	ReportPath   string    `json:"report_path,omitempty"`
	FindingsJSON string    `json:"-"`
}

// StartScanHistory inserts a running scan row and returns its id.
func (d *DB) StartScanHistory(ctx context.Context, target string) (int64, error) {
	res, err := d.sql.ExecContext(ctx, `
		INSERT INTO scan_history (started_at, target, status, finding_count, report_path, findings_json)
		VALUES (datetime('now'), ?, 'running', 0, '', '[]')
	`, target)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScanHistory marks a scan complete with findings snapshot.
func (d *DB) FinishScanHistory(ctx context.Context, id int64, findingCount int, reportPath, findingsJSON, status string) error {
	if status == "" {
		status = "ok"
	}
	_, err := d.sql.ExecContext(ctx, `
		UPDATE scan_history
		SET finished_at = datetime('now'),
		    finding_count = ?,
		    report_path = ?,
		    findings_json = ?,
		    status = ?
		WHERE id = ?
	`, findingCount, reportPath, findingsJSON, status, id)
	return err
}

// ListScanHistory returns recent scans, optionally filtered by target.
func (d *DB) ListScanHistory(ctx context.Context, target string, limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	var (
		rows *sql.Rows
		err  error
	)
	if target == "" {
		rows, err = d.sql.QueryContext(ctx, `
			SELECT id, started_at, COALESCE(finished_at, ''), target, finding_count, status, report_path, findings_json
			FROM scan_history
			ORDER BY id DESC
			LIMIT ?
		`, limit)
	} else {
		rows, err = d.sql.QueryContext(ctx, `
			SELECT id, started_at, COALESCE(finished_at, ''), target, finding_count, status, report_path, findings_json
			FROM scan_history
			WHERE target = ?
			ORDER BY id DESC
			LIMIT ?
		`, target, limit)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []ScanRecord
	for rows.Next() {
		var r ScanRecord
		var started, finished string
		if err := rows.Scan(&r.ID, &started, &finished, &r.Target, &r.FindingCount, &r.Status, &r.ReportPath, &r.FindingsJSON); err != nil {
			return nil, err
		}
		r.StartedAt = parseSQLiteTime(started)
		if finished != "" {
			r.FinishedAt = parseSQLiteTime(finished)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LastTwoScans returns the two most recent completed scans for a target.
func (d *DB) LastTwoScans(ctx context.Context, target string) (latest, previous *ScanRecord, err error) {
	rows, err := d.ListScanHistory(ctx, target, 2)
	if err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, nil
	}
	latest = &rows[0]
	if len(rows) > 1 {
		previous = &rows[1]
	}
	return latest, previous, nil
}

func parseSQLiteTime(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		time.RFC3339,
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
