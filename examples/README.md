# Foxhole examples

Fixtures and configs used by local demos and GitHub Actions.

| Path | What it shows | Workflow |
|------|---------------|----------|
| [go-demo](go-demo/) | Offline NVD/OSV vuln match (`github.com/vulnerable/lib`) | [capabilities-demo.yml](../.github/workflows/capabilities-demo.yml), Docker/Podman demo |
| [phase2-findings](phase2-findings/) | Secret + EOL findings | [phase2-findings-demo.yml](../.github/workflows/phase2-findings-demo.yml), capabilities demo |
| [policy.yaml](policy.yaml) | CI fail-on policy (`exit 2`) | capabilities demo |
| [foxhole.yaml](foxhole.yaml) | Sample config file | — |
| [jenkins/](jenkins/) | Jenkins Declarative Pipeline + policy | — |

## Quick local runs

```bash
go build -o bin/foxhole ./cmd/foxhole
./bin/foxhole db update examples/go-demo --offline

# Vulns + reports
./bin/foxhole examples/go-demo --offline --secrets=false --eol=false --report console,json,sarif

# Secrets + EOL
./bin/foxhole examples/phase2-findings --offline

# Archive / history / diff
./bin/foxhole examples/go-demo --offline --archive
./bin/foxhole history
./bin/foxhole diff last examples/go-demo

# Policy gate (expect exit code 2)
./bin/foxhole examples/phase2-findings --offline --fail-on high; echo exit:$?

# REST API
./bin/foxhole serve --addr :8080
```

## GitHub Actions

| Workflow | Purpose |
|----------|---------|
| [ci.yml](../.github/workflows/ci.yml) | `go test` + golangci-lint on every PR/push |
| [publish-image.yml](../.github/workflows/publish-image.yml) | Build/push `ghcr.io/jasonflaherty/foxhole:latest` (+ version tags) |
| [capabilities-demo.yml](../.github/workflows/capabilities-demo.yml) | Full product tour (reports, archive, policy, notify mock, API) |
| [phase2-findings-demo.yml](../.github/workflows/phase2-findings-demo.yml) | Focused secret + EOL assertion |
| [vulnerable-target-scan.yml](../.github/workflows/vulnerable-target-scan.yml) | Optional Juice Shop / NodeGoat online scan |

Run **Actions → Capabilities demo → Run workflow** for the full tour.

## Jenkins

See [jenkins/](jenkins/) for a Declarative `Jenkinsfile`, policy file, and
integration notes (Docker agent, exit codes, artifacts).
