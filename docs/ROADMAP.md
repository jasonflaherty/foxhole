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

### Enterprise readiness — Phase A (near-term Jenkins ROI)
- [x] Image pin (tag/digest) + optional cosign in Jenkins docs
- [x] Stale-DB gate (`last_sync_at`, `--max-db-age` / `FOXHOLE_MAX_DB_AGE`, exit **1**)
- [x] `--split-reports` per-kind JSON artifacts
- [x] Policy suppressions with `until` / `ticket` / `reason` (+ legacy `ignore`)
- [x] Jenkins shared library step `foxholeScan` + Warnings NG / HTML Publisher docs

### Enterprise readiness — Phase B (medium-term)
- [x] `foxhole serve` Bearer token (`FOXHOLE_API_TOKEN`) on mutating/history routes
- [x] Stable JSON/webhook export envelope (`schema_version` 1.0.0)
- [x] Manifest-declared license signal (npm `package.json`) with LICENSE-file fallback
- [x] `--policy-dir` org policy pack merge

### Differentiation — Phase C–F (governance)
- [x] Evidence packs (`--evidence`) with DB hash, policy fingerprint, SARIF, suppressions
- [x] Policy `id`/`version` + `foxhole policy validate`
- [x] Last-green history + `--github-diff` open/close issues by fingerprint
- [x] Deterministic `--triage` / optional `--triage-ai` (AI explains; Foxhole gates)
- [x] `foxhole db export` / `db import` bundles + cosign sign image/DB workflows
- [x] Air-gap runbook ([AIRGAP.md](AIRGAP.md))

**Release:** `v0.4.0` — curated cloud/token secret pack + Juice Shop bake-off.  
**v1 gate:** [V1.md](V1.md) — CI gate + evidence + air-gap; soak then tag `v1.0.0`.

## Later / deeper

- Full online EPSS CSV bulk import; richer SBOM ingestion
- Organization multi-tenant dashboard and scheduled scans
- Automated PR creation for dependency upgrades
- Reachability analysis; multi-tenant SaaS; replacing Dependabot/Trivy
