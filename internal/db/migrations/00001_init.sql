-- +goose Up
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS providers (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    last_updated TEXT,
    content_sha256 TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY NOT NULL,
    source TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    cvss_score REAL,
    published TEXT,
    modified TEXT,
    raw_json TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY NOT NULL,
    source TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    published TEXT,
    modified TEXT,
    aliases TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    purl TEXT NOT NULL DEFAULT '',
    UNIQUE(ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS package_vulns (
    package_id INTEGER NOT NULL,
    vuln_id TEXT NOT NULL,
    vuln_type TEXT NOT NULL CHECK (vuln_type IN ('cve', 'advisory')),
    introduced TEXT NOT NULL DEFAULT '',
    fixed TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (package_id, vuln_id, vuln_type),
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS aliases (
    alias TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    PRIMARY KEY (alias, vuln_id)
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY NOT NULL,
    score REAL NOT NULL,
    percentile REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY NOT NULL,
    vendor_project TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    date_added TEXT,
    due_date TEXT,
    known_ransomware TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS eol (
    product TEXT NOT NULL,
    cycle TEXT NOT NULL,
    eol TEXT,
    latest TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (product, cycle)
);

CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    spdx_id TEXT NOT NULL DEFAULT '',
    risk TEXT NOT NULL DEFAULT '',
    osi_approved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS secret_rules (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    report_path TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_advisories_source ON advisories(source);
CREATE INDEX IF NOT EXISTS idx_packages_eco_name ON packages(ecosystem, name);
CREATE INDEX IF NOT EXISTS idx_package_vulns_vuln ON package_vulns(vuln_id);
CREATE INDEX IF NOT EXISTS idx_aliases_vuln ON aliases(vuln_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_started ON scan_history(started_at);

INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', '1');
INSERT OR IGNORE INTO metadata (key, value) VALUES ('created_at', datetime('now'));

-- +goose Down
DROP INDEX IF EXISTS idx_scan_history_started;
DROP INDEX IF EXISTS idx_aliases_vuln;
DROP INDEX IF EXISTS idx_package_vulns_vuln;
DROP INDEX IF EXISTS idx_packages_eco_name;
DROP INDEX IF EXISTS idx_advisories_source;
DROP INDEX IF EXISTS idx_cves_severity;
DROP TABLE IF EXISTS scan_history;
DROP TABLE IF EXISTS secret_rules;
DROP TABLE IF EXISTS licenses;
DROP TABLE IF EXISTS eol;
DROP TABLE IF EXISTS kev;
DROP TABLE IF EXISTS epss;
DROP TABLE IF EXISTS aliases;
DROP TABLE IF EXISTS package_vulns;
DROP TABLE IF EXISTS packages;
DROP TABLE IF EXISTS advisories;
DROP TABLE IF EXISTS cves;
DROP TABLE IF EXISTS providers;
DROP TABLE IF EXISTS metadata;
