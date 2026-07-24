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
- [x] `foxhole serve` + embedded dashboard at `/`
- [x] Plugin SDK stubs in `pkg/plugin` (scanner / reporter / notifier registry)

### Phase 5 (partial) — Policy engine
- [x] Severity fail-on gate (`--fail-on`, `--policy`, `--fail-on-kind`) with CI exit code **2**
- [ ] AI remediation
- [ ] Broader enterprise integrations

## Later

- Remaining Phase 5: AI remediation, enterprise integrations
- Design-book backlog: KEV/EPSS/licenses/SBOM, Slack/Discord, richer dashboard
