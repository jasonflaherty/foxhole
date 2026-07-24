# Foxhole

Offline-first software supply chain scanner for local projects and CI.

Scan a repo for dependency vulnerabilities, secrets, end-of-life runtimes,
risky licenses, and Dockerfile misconfigs. Results land in **one findings list**
(each item has a `kind`), then you choose how to report, gate CI, notify, or
remediate.

**Image:** `ghcr.io/jasonflaherty/foxhole:latest` · **License:** MIT

## Install

```bash
# From source
go install github.com/jasonflaherty/foxhole/cmd/foxhole@latest

# Or container
docker pull ghcr.io/jasonflaherty/foxhole:latest
# podman pull ghcr.io/jasonflaherty/foxhole:latest
```

From this repo:

```bash
git clone https://github.com/jasonflaherty/foxhole.git
cd foxhole
go build -o bin/foxhole ./cmd/foxhole
```

## First scan (two steps)

1. **Refresh the local DB** (network once; stores under `~/.foxhole/foxhole.db`):

```bash
foxhole db update
# or offline seeds only:
foxhole db update --offline
```

2. **Scan a path**:

```bash
foxhole .
foxhole ./my-app --offline
```

Every scan also records history in SQLite (`foxhole history`).

### What a finding looks like

Findings are **not** split into separate Dependabot-style logs. One report
includes everything; filter by `kind` in JSON if you need streams.

| `kind` | Meaning |
|--------|---------|
| `vuln` | Dependency / advisory (NVD, OSV, GHSA) |
| `secret` | Credential pattern match |
| `eol` | End-of-life runtime (e.g. old Go/Node) |
| `misconfig` | Dockerfile hardening issues |
| `license` | High-risk license signals |

Console example:

```text
[HIGH] CVE-2024-… (vuln)
  package: github.com/vulnerable/lib@v1.0.0 (Go)
[CRITICAL] aws-access-key (secret)
  path: demo.env:4
[HIGH] go@1.20 (eol)
  product: go@1.20 eol=2024-02-01
```

## Common workflows

### Reports

```bash
# Console only (default)
foxhole .

# Files next to cwd: foxhole-report.json, .sarif, etc.
foxhole . --report console,json,sarif,html,markdown

# CI / SBOM-oriented
foxhole . --report console,junit,cyclonedx,spdx
```

### CI gate (fail the build)

```bash
foxhole . --fail-on high          # exit 2 if severity ≥ high
foxhole . --policy policy.yaml    # see examples/policy.yaml
```

| Exit | Meaning |
|------|---------|
| `0` | OK (or no policy) |
| `1` | Tool / usage error |
| `2` | Policy failed |

Jenkins copy-paste: [examples/jenkins/](examples/jenkins/).

### History, diff, archive

```bash
foxhole . --archive                    # archive/YYYY/MM/DD/*
foxhole history
foxhole diff last .                    # compare last two scans for that path
```

### Remediation notes

```bash
foxhole . --remediate                  # foxhole-remediation.md + .json
foxhole . --remediate --remediate-ai    # needs FOXHOLE_AI_API_KEY / OPENAI_API_KEY
```

### Notifications (optional)

Pattern for every channel: **set env vars → pass the matching flag**.
Nothing is sent unless you pass the flag. Failed notifies are logged; they do
not fail the scan by themselves (policy/`--fail-on` still controls exit code).

You can combine flags: `foxhole . --slack --teams --github`.

#### Slack

1. Slack app → **Incoming Webhooks** → add to a channel → copy URL.
2. Run:

```bash
export FOXHOLE_SLACK_WEBHOOK='https://hooks.slack.com/services/T…/B…/…'
foxhole . --slack
```

#### Microsoft Teams

1. Channel → **Connectors** / **Workflows** → Incoming Webhook → copy URL.
2. Run:

```bash
export FOXHOLE_TEAMS_WEBHOOK='https://outlook.office.com/webhook/…'
foxhole . --teams
```

#### Discord

1. Channel settings → **Integrations** → **Webhooks** → New → copy URL.
2. Run:

```bash
export FOXHOLE_DISCORD_WEBHOOK='https://discord.com/api/webhooks/…/…'
foxhole . --discord
```

#### GitHub Issues

Opens one issue on the target repo with a findings summary.

1. Create a PAT (or use `GITHUB_TOKEN` in Actions) with `issues: write`.
2. Run:

```bash
export FOXHOLE_GITHUB_TOKEN='ghp_…'          # or GITHUB_TOKEN
export FOXHOLE_GITHUB_REPO='owner/repo'      # or GITHUB_REPOSITORY
foxhole . --github
```

#### GitHub Checks

Posts a **Check Run** on a commit (CI status UI). Needs repo + commit SHA.

```bash
export FOXHOLE_GITHUB_TOKEN='ghp_…'          # needs checks:write
export FOXHOLE_GITHUB_REPO='owner/repo'
export FOXHOLE_GIT_SHA="$(git rev-parse HEAD)"   # or GITHUB_SHA in Actions
foxhole . --github-checks
```

GitHub Actions example:

```yaml
- name: Foxhole scan + Check Run
  env:
    FOXHOLE_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    FOXHOLE_GITHUB_REPO: ${{ github.repository }}
    FOXHOLE_GIT_SHA: ${{ github.sha }}
  run: |
    foxhole . --offline --github-checks --fail-on high
```

#### Generic webhook

POSTs JSON `{summary, target, packages, findings}` to any HTTPS endpoint.

```bash
export FOXHOLE_WEBHOOK_URL='https://example.com/hooks/foxhole'
foxhole . --webhook
```

#### Email (SMTP)

```bash
export FOXHOLE_SMTP_HOST='smtp.example.com'
export FOXHOLE_SMTP_PORT='587'                 # default 587
export FOXHOLE_SMTP_USER='foxhole@example.com'
export FOXHOLE_SMTP_PASS='…'
export FOXHOLE_EMAIL_FROM='foxhole@example.com'
export FOXHOLE_EMAIL_TO='sec@example.com,ops@example.com'
foxhole . --email
```

#### Docker / CI tip

Pass the same env into the container:

```bash
docker run --rm \
  -e FOXHOLE_SLACK_WEBHOOK \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD:/work:ro" \
  ghcr.io/jasonflaherty/foxhole:latest /work --offline --slack
```

### Toggle scanners

All of these default **on** except where noted:

```bash
foxhole . --secrets=false --eol=false --misconfig=false --licenses=false
foxhole . --enrich=false    # skip KEV/EPSS enrichment on vulns
```

### REST API + dashboard

```bash
foxhole serve --addr :8080
# open http://localhost:8080
```

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Dashboard |
| `GET` | `/health` | Liveness |
| `GET` | `/version` | Version |
| `GET` | `/history` | Scan history |
| `POST` | `/scan` | Run scan |
| `POST` | `/db/update` | Refresh DB |

### Docker / Podman

```bash
# Published CLI
docker run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD:/work:ro" \
  ghcr.io/jasonflaherty/foxhole:latest /work --offline

# Built-in offline demo
./docker/run-demo.sh
```

More volume/mount recipes: [docker/README.md](docker/README.md).

## Try the fixtures in this repo

```bash
./bin/foxhole db update examples/go-demo --offline
./bin/foxhole examples/go-demo --offline --secrets=false --eol=false

./bin/foxhole examples/phase2-findings --offline   # secret + EOL demo
```

Index of demos, Jenkins, and Actions: [examples/README.md](examples/README.md).

## Configuration

Precedence: **flags > `FOXHOLE_*` env > `foxhole.yaml`**

| Setting | Flag / env | Default |
|---------|------------|---------|
| SQLite DB | `--db-path` / `FOXHOLE_DB_PATH` | `~/.foxhole/foxhole.db` |
| Offline | `--offline` / `FOXHOLE_OFFLINE` | `false` |
| Reports | `--report` / `FOXHOLE_REPORT` | `console` |
| NVD API key | `--nvd-api-key` / `FOXHOLE_NVD_API_KEY` | empty |
| Archive dir | `--archive-dir` / `FOXHOLE_ARCHIVE_DIR` | `archive` |
| Policy file | `--policy` / `FOXHOLE_POLICY` | empty |
| Fail-on severity | `--fail-on` / `FOXHOLE_FAIL_ON` | empty |

Sample config: [examples/foxhole.yaml](examples/foxhole.yaml).

## Develop this repo

```bash
go test ./...
golangci-lint run
go build -o bin/foxhole ./cmd/foxhole
```

CI runs tests/lint on every PR. Optional demos (capabilities, Juice Shop) live under
[`.github/workflows/`](.github/workflows/).

## Docs

| Doc | Contents |
|-----|----------|
| [docs/ROADMAP.md](docs/ROADMAP.md) | What’s shipped |
| [docs/Foxhole_Design_Book.md](docs/Foxhole_Design_Book.md) | Architecture |
| [examples/](examples/) | Fixtures + Jenkins |
| [docker/](docker/) | Images and Podman |
| [pkg/plugin](pkg/plugin) | Extension SDK stubs |
| [pkg/provider](pkg/provider) | NVD / OSV / KEV / EPSS / GHSA |

## License

MIT — see [LICENSE](LICENSE).
