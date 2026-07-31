# Foxhole

Offline-first supply chain scanner for local projects and CI.

Foxhole scans a workspace for dependency vulns, secrets, EOL runtimes, risky
licenses, and Dockerfile issues. Everything lands in **one findings list**
(tagged by `kind`). You then report, gate the build, notify, or export audit
evidence—deterministically, with an optional local vuln DB that works offline.

| | |
|--|--|
| **Image** | `ghcr.io/jasonflaherty/foxhole` (and Docker Hub when configured) |
| **License** | MIT |
| **Not this** | Not a SaaS dashboard, Dependabot, or image scanner like Trivy |

## Quick start (5 minutes)

From this repo:

```bash
git clone https://github.com/jasonflaherty/foxhole.git
cd foxhole
go build -o bin/foxhole ./cmd/foxhole

# 1) Load demo vuln data (no network)
./bin/foxhole db update examples/go-demo --offline

# 2) Scan the vulnerable Go fixture
./bin/foxhole examples/go-demo --offline --secrets=false --eol=false

# 3) Secrets + EOL fixture
./bin/foxhole examples/phase2-findings --offline
```

Or install the binary / pull the image:

```bash
go install github.com/jasonflaherty/foxhole/cmd/foxhole@latest
# or
docker pull ghcr.io/jasonflaherty/foxhole:v0.4.0
# Docker Hub (if published): docker pull <hub-user>/foxhole:v0.4.0
```

## Mental model

```text
db update  →  scan path  →  report / policy / evidence / notify
                 │
                 └─ findings[] each with kind: vuln | secret | eol | misconfig | license
```

1. **`foxhole db update`** — refresh the local SQLite DB (`~/.foxhole/foxhole.db` by default). Use `--offline` for embedded demo seeds; for real coverage, update online (or import a [DB bundle](docs/AIRGAP.md)).
2. **`foxhole <path>`** — scan. Always writes history (`foxhole history`).
3. **Optional flags** — reports, CI policy, evidence pack, triage, notifications.

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | OK (or no policy configured) |
| `1` | Tool / usage error, or **stale DB** (`--max-db-age`) |
| `2` | Policy gate failed (`--fail-on` / `--policy`) |

Detection is always deterministic. `--triage-ai` / `--remediate-ai` only draft text; they never change pass/fail.

## Findings

| `kind` | Meaning |
|--------|---------|
| `vuln` | Dependency advisory (NVD / OSV / GHSA) |
| `secret` | Credential pattern (curated AWS/GCP/Azure/GitHub/JWT/PEM/… rules) |
| `eol` | End-of-life runtime |
| `misconfig` | Dockerfile hardening |
| `license` | High-risk license signal |

```text
[HIGH] CVE-2024-… (vuln)
  package: github.com/vulnerable/lib@v1.0.0 (Go)
[CRITICAL] aws-access-key (secret)
  path: demo.env:4
```

## Everyday use

### Scan and report

```bash
foxhole .                                          # console
foxhole . --report console,json,sarif,html         # files in cwd
foxhole . --report console,junit,cyclonedx,spdx    # CI / SBOM
foxhole . --secrets=false --eol=false              # turn scanners off
```

### Fail the build (policy)

```bash
foxhole . --fail-on high
foxhole . --policy examples/policy.yaml
foxhole . --policy-dir examples/policy-pack     # merge org YAML packs
foxhole policy validate examples/policy-pack    # fingerprint + expired suppressions
```

Policy YAML supports `fail_on`, `kinds`, permanent `ignore`, and time-bounded
`suppressions` (`until` / `ticket` / `reason`). See [examples/policy.yaml](examples/policy.yaml).

### Audit evidence

```bash
foxhole . --policy examples/policy.yaml --evidence --split-reports --max-db-age 720h
```

Writes `foxhole-evidence/` (manifest with DB hash + policy fingerprint, SARIF,
suppressions) plus per-kind JSON (`foxhole-secrets.json`, …).

### Triage (explain, don’t detect)

```bash
foxhole . --triage                 # foxhole-triage.md + .json (deterministic)
foxhole . --triage --triage-ai     # optional LLM prose; needs FOXHOLE_AI_API_KEY
```

### Diff-driven GitHub issues

```bash
export FOXHOLE_GITHUB_TOKEN=… FOXHOLE_GITHUB_REPO=owner/repo
foxhole . --github-diff --triage   # one issue per NEW finding vs last green; close when fixed
foxhole . --github                 # legacy: one summary issue with everything
```

### History and archive

```bash
foxhole . --archive
foxhole history
foxhole diff last .
```

## CI recipes

**Minimal gate**

```bash
foxhole db update
foxhole . --fail-on high --report console,sarif
```

**Regulated / Jenkins-style**

```bash
foxhole db update   # or: foxhole db import ./foxhole-db.tar.gz
foxhole . --offline --max-db-age 720h \
  --policy-dir ./policy-pack \
  --evidence --split-reports \
  --report console,json,sarif,html
```

Copy-paste Jenkins + shared library: [examples/jenkins/](examples/jenkins/).  
Air-gap (signed image + DB bundle): [docs/AIRGAP.md](docs/AIRGAP.md).  
Feature demos in Actions: [examples/README.md](examples/README.md).

**GitHub Actions (Check Run)**

```yaml
- run: foxhole . --offline --github-checks --fail-on high
  env:
    FOXHOLE_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    FOXHOLE_GITHUB_REPO: ${{ github.repository }}
    FOXHOLE_GIT_SHA: ${{ github.sha }}
```

## Notifications

Set env → pass the matching flag. Nothing is sent without the flag. Notify
failures are logged; they do **not** change the exit code.

| Flag | Env |
|------|-----|
| `--slack` | `FOXHOLE_SLACK_WEBHOOK` |
| `--teams` | `FOXHOLE_TEAMS_WEBHOOK` |
| `--discord` | `FOXHOLE_DISCORD_WEBHOOK` |
| `--webhook` | `FOXHOLE_WEBHOOK_URL` |
| `--email` | `FOXHOLE_SMTP_*`, `FOXHOLE_EMAIL_FROM`, `FOXHOLE_EMAIL_TO` |
| `--github` / `--github-diff` | `FOXHOLE_GITHUB_TOKEN`, `FOXHOLE_GITHUB_REPO` |
| `--github-checks` | same + `FOXHOLE_GIT_SHA` |

```bash
export FOXHOLE_SLACK_WEBHOOK='https://hooks.slack.com/services/…'
foxhole . --slack
```

Container tip: pass the same env into `docker run -e FOXHOLE_SLACK_WEBHOOK …`.

## Database commands

```bash
foxhole db update [path]           # refresh providers (online or --offline seeds)
foxhole db verify                  # integrity + last sync age
foxhole db export -o bundle.tar.gz # air-gap bundle
foxhole db import bundle.tar.gz    # install bundle into --db-path
```

## REST API (`foxhole serve`)

For trusted networks only. With `FOXHOLE_API_TOKEN` set, `/scan`, `/db/update`,
and `/history` require `Authorization: Bearer <token>` (or `X-Foxhole-Token`).
`/health`, `/version`, and `/` stay public.

```bash
export FOXHOLE_API_TOKEN='…'    # optional
foxhole serve --addr :8080
```

## Docker / Podman

```bash
docker run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD:/work:ro" \
  ghcr.io/jasonflaherty/foxhole:v0.4.0 /work --offline

./docker/run-demo.sh    # offline go-demo in one shot
```

More mounts and cosign verify: [docker/README.md](docker/README.md).

## Configuration

Precedence: **flags > `FOXHOLE_*` env > `foxhole.yaml`**

| Setting | Flag / env | Default |
|---------|------------|---------|
| SQLite DB | `--db-path` / `FOXHOLE_DB_PATH` | `~/.foxhole/foxhole.db` |
| Offline | `--offline` / `FOXHOLE_OFFLINE` | `false` |
| Reports | `--report` / `FOXHOLE_REPORT` | `console` |
| NVD API key | `--nvd-api-key` / `FOXHOLE_NVD_API_KEY` | empty |
| Policy file | `--policy` / `FOXHOLE_POLICY` | empty |
| Policy pack | `--policy-dir` / `FOXHOLE_POLICY_DIR` | empty |
| Fail-on | `--fail-on` / `FOXHOLE_FAIL_ON` | empty |
| Max DB age | `--max-db-age` / `FOXHOLE_MAX_DB_AGE` | empty (off) |
| Evidence | `--evidence` / `FOXHOLE_EVIDENCE` | `false` |
| Triage | `--triage` / `--triage-ai` | `false` |
| Serve token | `FOXHOLE_API_TOKEN` | empty (auth off) |

Sample file: [examples/foxhole.yaml](examples/foxhole.yaml).

## Docs map

| Doc | When to read it |
|-----|-----------------|
| [examples/README.md](examples/README.md) | Fixtures + which Actions demo to run |
| [examples/jenkins/](examples/jenkins/) | Jenkins pipeline / shared lib |
| [docs/AIRGAP.md](docs/AIRGAP.md) | Offline / air-gapped CI |
| [docker/README.md](docker/README.md) | Images, volumes, cosign |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What’s shipped |
| [docs/Foxhole_Design_Book.md](docs/Foxhole_Design_Book.md) | Architecture |

## Develop

```bash
go test ./...
golangci-lint run
go build -o bin/foxhole ./cmd/foxhole
```

## License

MIT — see [LICENSE](LICENSE).
