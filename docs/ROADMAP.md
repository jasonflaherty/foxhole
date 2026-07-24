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
- [ ] Commit/push Phase 2 to `main` if still local-only

## Next — Phase 3

Make notifications and historical scans work:

1. **`--archive`** — write reports under `archive/YYYY/MM/DD/`
2. **`foxhole history`** — persist/list rows in `scan_history`
3. **`foxhole diff last`** — compare consecutive scans for a target
4. **Notifiers** — wire `--github` / `--teams` / `--email` via `internal/notify`

How to start Phase 3:

```bash
# after Phase 2 is on main
foxhole . --report json,html   # baseline today
# then implement archive → history → diff → notifiers
```

## Later

- **Phase 4:** REST API (Chi), dashboard, plugin SDK
- **Phase 5:** AI remediation, policy engine, enterprise integrations
