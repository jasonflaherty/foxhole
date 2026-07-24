# Foxhole

Offline-first, open-source software supply chain security scanner.

Foxhole combines vulnerability (NVD/OSV), secret, and EOL scanning with
multi-format reporting, scan history/diff, notifications, and a local REST API.

## Quick start

```bash
go install github.com/jasonflaherty/foxhole/cmd/foxhole@latest

# Update local vulnerability database (requires network)
foxhole db update

# Scan the current directory (works offline against local DB)
foxhole .
foxhole . --offline
foxhole . --report console,json,sarif
foxhole . --archive
```

### Container demo (Docker or Podman)

```bash
# Published CLI image (after Actions → Publish container image runs on main)
docker pull ghcr.io/jasonflaherty/foxhole:latest
docker run --rm ghcr.io/jasonflaherty/foxhole:latest version

# Local offline go-demo
docker build -t foxhole-go-demo -f docker/Dockerfile.demo .
docker run --rm foxhole-go-demo

# or: podman build -t foxhole-go-demo -f docker/Dockerfile.demo .
#     podman run --rm foxhole-go-demo
```

See [docker/README.md](docker/README.md) for the CLI image, GHCR pull, and volume mounts.

## Configuration

Precedence: **CLI flags > environment variables (`FOXHOLE_*`) > `foxhole.yaml`**

See [examples/foxhole.yaml](examples/foxhole.yaml).

| Flag / env | Description |
|---|---|
| `--db-path` / `FOXHOLE_DB_PATH` | SQLite path (default `~/.foxhole/foxhole.db`) |
| `--offline` / `FOXHOLE_OFFLINE` | Disable network access |
| `--log-level` / `FOXHOLE_LOG_LEVEL` | Zap log level |
| `--nvd-api-key` / `FOXHOLE_NVD_API_KEY` | Optional NVD API key |
| `--report` / `FOXHOLE_REPORT` | Formats: `console,json,markdown,html,sarif` |
| `--secrets` / `FOXHOLE_SECRETS` | Enable secret scanning (default true) |
| `--eol` / `FOXHOLE_EOL` | Enable EOL checks (default true) |
| `--archive` | Write reports under `archive/YYYY/MM/DD/` |
| `--archive-dir` / `FOXHOLE_ARCHIVE_DIR` | Archive base directory (default `archive`) |
| `--github` | Open a GitHub issue (`FOXHOLE_GITHUB_TOKEN`, `FOXHOLE_GITHUB_REPO`) |
| `--teams` | Post to Teams (`FOXHOLE_TEAMS_WEBHOOK`) |
| `--email` | SMTP email (`FOXHOLE_SMTP_*`, `FOXHOLE_EMAIL_FROM`, `FOXHOLE_EMAIL_TO`) |
| `--fail-on` / `FOXHOLE_FAIL_ON` | CI gate: fail if findings ≥ severity (`high`, `any`, …) |
| `--policy` / `FOXHOLE_POLICY` | Path to policy YAML (`fail_on`, `kinds`, `ignore`) |
| `--fail-on-kind` | Limit gate to kinds (`vuln`, `secret`, `eol`; repeatable) |

## CLI

```bash
foxhole .                                    # scan path (also records history)
foxhole . --report json,html,sarif           # write foxhole-report.* files
foxhole . --archive                          # also write archive/YYYY/MM/DD/*
foxhole . --fail-on high                     # exit 2 if high+ findings (CI)
foxhole . --policy examples/policy.yaml      # same via YAML
foxhole . --secrets=false --eol=false        # vulns only
foxhole history                              # list recent scans
foxhole diff last .                          # compare last two scans for path
foxhole serve --addr :8080                   # REST API + dashboard
foxhole db update                            # refresh NVD + OSV + seed secrets/EOL
foxhole db update ./app --direct-only --max-packages 60
foxhole db verify
foxhole version
```

### Policy / CI exit codes

| Code | Meaning |
|---|---|
| `0` | Success (or no policy configured) |
| `1` | Runtime / usage error |
| `2` | Policy gate failed |

See [examples/policy.yaml](examples/policy.yaml). For Jenkins pipelines (Docker
agent, artifacts, shared DB), see [examples/jenkins/](examples/jenkins/).

### REST API (`foxhole serve`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/health` | Liveness |
| `GET` | `/version` | Build version |
| `GET` | `/history` | Scan history (`?target=`) |
| `POST` | `/scan` | Run a scan (`{"target":".","offline":true}`) |
| `POST` | `/db/update` | Refresh providers (`?offline=true`) |

### Plugin SDK

Extension contracts live in [`pkg/plugin`](pkg/plugin): register custom scanners,
reporters, and notifiers. Vulnerability data providers remain in [`pkg/provider`](pkg/provider).

### Phase 2 findings demo (secrets + EOL)

GitHub Actions workflow [phase2-findings-demo.yml](.github/workflows/phase2-findings-demo.yml) scans [examples/phase2-findings](examples/phase2-findings) and expects both **secret** and **EOL** hits.

- **Actions → Phase 2 findings demo → Run workflow**
- Also runs on PRs that touch scan/seeds/report code

### Full capabilities demo

[capabilities-demo.yml](.github/workflows/capabilities-demo.yml) walks through vulns, secrets/EOL, all report formats, archive/history/diff, policy exit `2`, mock Teams notify, and the REST API. See [examples/README.md](examples/README.md).

- **Actions → Capabilities demo → Run workflow**

### Scan a known-vulnerable app (CI)

GitHub Actions workflow [vulnerable-target-scan.yml](.github/workflows/vulnerable-target-scan.yml) builds Foxhole and scans **OWASP Juice Shop** or **NodeGoat**.

- **Actions → Vulnerable target scan → Run workflow**
- Weekly schedule (Mondays)
- Uploads `scan-results.txt` as an artifact

## Development

```bash
go test ./...
golangci-lint run
go build -o bin/foxhole ./cmd/foxhole
```

## Architecture

See [docs/Foxhole_Design_Book.md](docs/Foxhole_Design_Book.md) and [docs/ROADMAP.md](docs/ROADMAP.md) (phase status).

## License

MIT — see [LICENSE](LICENSE).
