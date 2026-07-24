# Foxhole Design Book

Version: 0.1 Draft

## Vision

Foxhole is a 100% open-source, offline-first software supply chain
security platform combining vulnerability, secret, EOL, SBOM, license,
and misconfiguration scanning with reporting and notifications.

## Guiding Principles

-   MIT or Apache-2.0 license
-   Modular plugin architecture
-   Container-first
-   Offline capable
-   No telemetry
-   Fast and deterministic
-   CI/CD native

# Architecture

## Core

-   CLI
-   Scan Engine
-   Rule Engine
-   Provider SDK
-   Reporter SDK
-   Archive Engine
-   Notification Engine
-   REST API
-   SQLite Database

## Providers

-   NVD
-   OSV
-   GHSA
-   CISA KEV
-   EPSS
-   EOL
-   Secret Rules
-   License Rules

Each provider implements: - Initialize - Update - Verify - Search -
Metadata

## Scanner Modules

-   Filesystem
-   Container
-   Repository
-   SBOM
-   Kubernetes
-   Terraform
-   Dockerfile
-   Secrets
-   EOL
-   Licenses

## Database

SQLite with migrations.

Tables: - metadata - providers - cves - advisories - packages -
aliases - epss - kev - eol - licenses - secret_rules - scan_history

30-day refresh maximum. SHA256 verification. Offline mode.

## CLI

Examples:

``` bash
foxhole .
foxhole . --archive
foxhole . --github
foxhole . --teams
foxhole . --email
foxhole . --report html,json,sarif
foxhole db update
foxhole history
foxhole diff last
```

## Configuration

Supports: - foxhole.yaml - Environment variables - CLI flags

## Reports

-   Console
-   JSON
-   Markdown
-   HTML
-   SARIF
-   CycloneDX
-   SPDX
-   JUnit

## Notifications

-   GitHub Issues
-   GitHub Checks
-   Email
-   Microsoft Teams
-   Slack
-   Discord
-   Webhooks

## Archive Layout

archive/YYYY/MM/DD/

Stores: - json - html - markdown - sarif - txt

## REST API

POST /scan POST /db/update GET /history GET /health GET /version

## Docker

Images: - foxhole-cli - foxhole-server - foxhole-db - foxhole-updater

Persistent volume: /var/lib/foxhole

## Coding Standards

Language: Go CLI: Cobra Config: Viper Router: Chi Logging: Zap Database:
SQLite

80%+ unit test coverage. Table-driven tests. golangci-lint.

## GitHub Roadmap

### Phase 1

-   CLI
-   Config
-   DB
-   NVD
-   OSV

### Phase 2

-   Secret scanning
-   EOL
-   Reports

### Phase 3

-   GitHub
-   Teams
-   Email
-   Archive
-   History

### Phase 4

-   REST API
-   Dashboard
-   Plugin SDK

### Phase 5

-   AI remediation
-   Policy engine
-   Enterprise integrations

## Future Ideas

-   AI-assisted remediation
-   PR creation
-   Automated dependency upgrades
-   Historical trends
-   Scheduled scans
-   Organization dashboard
-   Multi-project inventory

## Appendix

Suggested repository layout:

cmd/ internal/ pkg/ docs/ docker/ examples/ .github/

This design book is intended to serve as the living architecture
document for the Foxhole project.
