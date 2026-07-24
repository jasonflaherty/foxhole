-- +goose Up
ALTER TABLE scan_history ADD COLUMN policy_passed INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS github_issue_map (
    fingerprint TEXT NOT NULL,
    repo TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    finding_id TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (fingerprint, repo)
);

-- +goose Down
DROP TABLE IF EXISTS github_issue_map;
-- SQLite cannot DROP COLUMN portably; leave policy_passed on downgrade.
