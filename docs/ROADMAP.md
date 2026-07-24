# Foxhole roadmap status

Living checklist aligned with [Foxhole_Design_Book.md](Foxhole_Design_Book.md).

## Done

### Phase 1 — Foundation
- [x] CLI (Cobra) + config (Viper: file / env / flags)
- [x] SQLite + goose migrations
- [x] NVD + OSV providers (online update, offline seeds, SHA256 verify)
- [x] Filesystem dependency discovery + vuln matching
- [x] Tests, golangci-lint, CI; Juice Shop workflow; container demo

### Phase 2 — Secrets, EOL, reports
- [x] Secret scanning (seeded regex rules)
- [x] EOL checks (seeded cycles + runtime pins)
- [x] Reports: console, JSON, Markdown, HTML, SARIF (`--report`)
- [x] CI demo workflow for secret + EOL ([phase2-findings-demo.yml](../.github/workflows/phase2-findings-demo.yml))

### Phase 3 — Archive, history, notifications
- [x] `--archive` / `--archive-dir` → `archive/YYYY/MM/DD/`
- [x] `foxhole history` (persists every scan to `scan_history`)
- [x] `foxhole diff last` (compare consecutive scans)
- [x] Notifiers: `--github` / `--teams` / `--email` via `internal/notify`

### Phase 4 — API, dashboard, plugin SDK
- [x] REST API (Chi): `POST /scan`, `POST /db/update`, `GET /history`, `GET /health`, `GET /version`
- [x] `foxhole serve` + dashboard with scan stats
- [x] Plugin SDK + `pluginadapt` wired into the scan engine

### Phase 5 — Policy, AI remediation, enterprise notify
- [x] Severity fail-on gate (`--fail-on`, `--policy`) with CI exit code **2**
- [x] `--remediate` / `--remediate-ai` (rule-based + optional OpenAI-compatible API)
- [x] Slack, Discord, generic webhook, GitHub Checks notifiers
- [x] Capabilities demo + Jenkins examples

### Design-book backlog (shipped baseline)
- [x] CISA KEV + EPSS enrichment (`--enrich`)
- [x] GHSA provider (local advisory store)
- [x] License risk seeds + scanner (`--licenses`)
- [x] Dockerfile misconfig scanner (`--misconfig`)
- [x] JUnit, CycloneDX, SPDX report formats
- [x] `Dockerfile.server` for API image
- [x] GHCR publish workflow (`:latest` + version tags)

## Later / deeper

- Full online EPSS CSV bulk import; richer SBOM ingestion
- Organization multi-tenant dashboard and scheduled scans
- Automated PR creation for dependency upgrades
