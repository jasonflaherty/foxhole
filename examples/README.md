# Foxhole examples

Fixtures, policies, and Jenkins samples. Use these to learn the product locally
or via GitHub Actions demos.

## Start here

```bash
go build -o bin/foxhole ./cmd/foxhole

# Vulnerable dependency (offline seeds)
./bin/foxhole db update examples/go-demo --offline
./bin/foxhole examples/go-demo --offline --secrets=false --eol=false

# Secrets + EOL
./bin/foxhole examples/phase2-findings --offline
```

Expect a HIGH vuln in `go-demo`, and secret/EOL hits in `phase2-findings`.

## Fixtures

| Path | What you learn |
|------|----------------|
| [go-demo/](go-demo/) | Offline vuln match (`github.com/vulnerable/lib`) |
| [phase2-findings/](phase2-findings/) | Secret + EOL findings |
| [policy.yaml](policy.yaml) | CI policy + suppressions (`exit 2`) |
| [policy-pack/](policy-pack/) | Org packs via `--policy-dir` |
| [foxhole.yaml](foxhole.yaml) | Sample config file |
| [jenkins/](jenkins/) | Declarative pipeline, shared lib, cosign, evidence |

## Feature walkthroughs (local)

```bash
# Policy gate (expect exit 2)
./bin/foxhole examples/phase2-findings --offline --policy examples/policy.yaml; echo exit:$?

# Org policy pack
./bin/foxhole policy validate examples/policy-pack
./bin/foxhole examples/phase2-findings --offline --policy-dir examples/policy-pack; echo exit:$?

# Evidence pack for auditors
./bin/foxhole examples/phase2-findings --offline --policy examples/policy.yaml --evidence --split-reports
ls foxhole-evidence/

# Triage drafts (deterministic; no API key)
./bin/foxhole examples/phase2-findings --offline --triage
ls foxhole-triage.*

# Air-gap style DB bundle
./bin/foxhole db export -o /tmp/foxhole-db.tar.gz
./bin/foxhole db import /tmp/foxhole-db.tar.gz --db-path /tmp/imported.db
./bin/foxhole examples/go-demo --db-path /tmp/imported.db --offline --secrets=false --eol=false --max-db-age 720h

# API (optional token)
FOXHOLE_API_TOKEN=dev ./bin/foxhole serve --addr :8080
```

## GitHub Actions demos (one workflow per function)

Run from **Actions → Demo — … → Run workflow**.

| Workflow | Function |
|----------|----------|
| [demo-evidence.yml](../.github/workflows/demo-evidence.yml) | `--evidence` + split reports |
| [demo-policy-pack.yml](../.github/workflows/demo-policy-pack.yml) | `policy validate` + `--policy-dir` |
| [demo-triage.yml](../.github/workflows/demo-triage.yml) | `--triage` |
| [demo-github-diff.yml](../.github/workflows/demo-github-diff.yml) | `--github-diff` open/close (mock API) |
| [demo-db-bundle.yml](../.github/workflows/demo-db-bundle.yml) | `db export`/`import` + stale DB |
| [demo-serve-auth.yml](../.github/workflows/demo-serve-auth.yml) | Serve API token |
| [capabilities-demo.yml](../.github/workflows/capabilities-demo.yml) | Combined product tour |
| [phase2-findings-demo.yml](../.github/workflows/phase2-findings-demo.yml) | Secret + EOL assertion |
| [vulnerable-target-scan.yml](../.github/workflows/vulnerable-target-scan.yml) | Optional Juice Shop / NodeGoat online scan |
| [compare-juice-shop.yml](../.github/workflows/compare-juice-shop.yml) | Foxhole vs TruffleHog vs Gitleaks on Juice Shop |
| [ci.yml](../.github/workflows/ci.yml) | Tests + lint |
| [publish-image.yml](../.github/workflows/publish-image.yml) | GHCR image + cosign |
| [publish-db-bundle.yml](../.github/workflows/publish-db-bundle.yml) | DB bundle release |

Air-gap runbook: [docs/AIRGAP.md](../docs/AIRGAP.md).  
Main usage guide: [README.md](../README.md).

## Jenkins

See [jenkins/](jenkins/) for a pinned-image `Jenkinsfile`, `vars/foxholeScan.groovy`,
Warnings NG / HTML Publisher notes, and evidence artifacts.
