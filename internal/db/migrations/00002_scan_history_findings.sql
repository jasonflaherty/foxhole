-- +goose Up
ALTER TABLE scan_history ADD COLUMN findings_json TEXT NOT NULL DEFAULT '[]';

-- +goose Down
-- SQLite cannot DROP COLUMN portably in older versions; leave column on down.
SELECT 1;
