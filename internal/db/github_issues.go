package db

import (
	"context"
	"database/sql"
)

// GitHubIssueRef maps a finding fingerprint to a GitHub issue.
type GitHubIssueRef struct {
	Fingerprint string
	Repo        string
	IssueNumber int
	Target      string
	FindingID   string
}

// UpsertGitHubIssue stores or updates a fingerprint→issue mapping.
func (d *DB) UpsertGitHubIssue(ctx context.Context, ref GitHubIssueRef) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO github_issue_map (fingerprint, repo, issue_number, target, finding_id, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(fingerprint, repo) DO UPDATE SET
			issue_number = excluded.issue_number,
			target = excluded.target,
			finding_id = excluded.finding_id,
			updated_at = excluded.updated_at
	`, ref.Fingerprint, ref.Repo, ref.IssueNumber, ref.Target, ref.FindingID)
	return err
}

// GetGitHubIssue looks up an issue by fingerprint and repo.
func (d *DB) GetGitHubIssue(ctx context.Context, fingerprint, repo string) (*GitHubIssueRef, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT fingerprint, repo, issue_number, target, finding_id
		FROM github_issue_map WHERE fingerprint = ? AND repo = ?
	`, fingerprint, repo)
	var ref GitHubIssueRef
	err := row.Scan(&ref.Fingerprint, &ref.Repo, &ref.IssueNumber, &ref.Target, &ref.FindingID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ref, nil
}
