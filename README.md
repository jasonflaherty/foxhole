# Foxhole

Offline-first, open-source software supply chain security scanner.

Foxhole combines vulnerability (NVD/OSV), secret, and EOL scanning with
multi-format reporting. Phase 2 adds secrets, end-of-life checks, and
console/JSON/Markdown/HTML/SARIF reports.

## Quick start

```bash
go install github.com/jasonflaherty/foxhole/cmd/foxhole@latest

# Update local vulnerability database (requires network)
foxhole db update

# Scan the current directory (works offline against local DB)
foxhole .
foxhole . --offline
foxhole . --report console,json,sarif
```

### Container demo (Docker or Podman)

```bash
docker build -t foxhole-go-demo -f docker/Dockerfile.demo .
docker run --rm foxhole-go-demo

# or: podman build -t foxhole-go-demo -f docker/Dockerfile.demo .
#     podman run --rm foxhole-go-demo
```

See [docker/README.md](docker/README.md) for the CLI image and volume mounts.

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

## CLI

```bash
foxhole .                                    # scan path
foxhole . --report json,html,sarif           # write foxhole-report.* files
foxhole . --secrets=false --eol=false        # vulns only
foxhole db update                            # refresh NVD + OSV + seed secrets/EOL
foxhole db update ./app --direct-only --max-packages 60
foxhole db verify
foxhole version
```

### Phase 2 findings demo (secrets + EOL)

GitHub Actions workflow [phase2-findings-demo.yml](.github/workflows/phase2-findings-demo.yml) scans [examples/phase2-findings](examples/phase2-findings) and expects both **secret** and **EOL** hits.

- **Actions → Phase 2 findings demo → Run workflow**
- Also runs on PRs that touch scan/seeds/report code

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
