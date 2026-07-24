# Jenkins CI/CD

Use Foxhole as a pipeline stage: pull a **pinned** image, optionally verify with
cosign, update (or reuse) the local vuln DB, scan the workspace, archive reports,
and fail the build on policy exit code **2** (or exit **1** for stale DB / infra).

No Jenkins plugin is required — only Docker (or a binary on the agent). Optional
[Warnings NG](https://plugins.jenkins.io/warnings-ng/) and
[HTML Publisher](https://plugins.jenkins.io/htmlpublisher/) improve UI evidence.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass (or no policy configured) |
| `1` | Runtime / usage / **stale DB** (`--max-db-age`) |
| `2` | Policy gate failed — fail the stage |

## Image pins and cosign

Published tags come from [`.github/workflows/publish-image.yml`](../../.github/workflows/publish-image.yml):
`:latest` on `main`, and version tags like `:v0.2.0` on `v*` releases.

**Prefer a version tag or digest** — never `:latest` in enterprise CI:

```bash
# Tag pin
export FOXHOLE_IMAGE=ghcr.io/jasonflaherty/foxhole:v0.2.0

# Immutable digest pin (recommended)
export FOXHOLE_IMAGE=ghcr.io/jasonflaherty/foxhole@sha256:<digest>
```

To require cosign on the agent before scan:

```bash
export FOXHOLE_REQUIRE_COSIGN=true
# Install cosign on the agent; verify fails the stage when required.
```

See also [docker/README.md](../../docker/README.md).

## Declarative pipeline (Docker)

Copy [Jenkinsfile](Jenkinsfile) into your app repo. Commit
[foxhole-policy.yaml](foxhole-policy.yaml) (or [../policy.yaml](../policy.yaml))
at the repo root.

Key flags in the sample:

- `--split-reports` — writes `foxhole-vulns.json`, `foxhole-secrets.json`, …
- `--max-db-age 720h` — exit **1** if DB older than 30 days
- `--fail-on high` / `--policy` — exit **2** on policy findings

### Shared library step

Copy [vars/foxholeScan.groovy](vars/foxholeScan.groovy) into a Jenkins shared
library `vars/` folder, then:

```groovy
@Library('your-shared-lib') _

pipeline {
  agent any
  stages {
    stage('Foxhole') {
      steps {
        foxholeScan(
          image: 'ghcr.io/jasonflaherty/foxhole:v0.2.0',
          failOn: 'high',
          kinds: ['vuln', 'secret'],
          requireCosign: false,
          maxDbAge: '720h',
          splitReports: true,
          policy: 'foxhole-policy.yaml',
        )
      }
    }
  }
  post {
    always {
      // Optional HTML Publisher
      // publishHTML(target: [
      //   reportDir: '.', reportFiles: 'foxhole-report.html',
      //   reportName: 'Foxhole', keepAll: true, allowMissing: true,
      // ])
      // Optional Warnings NG (SARIF)
      // recordIssues(tools: [sarif(pattern: 'foxhole-report.sarif')], aggregatingResults: true)
    }
  }
}
```

## Multi-gate pattern (secrets vs vulns)

1. **One scan, split artifacts** — `--split-reports`, then archive and gate downstream
   jobs on `foxhole-secrets.json` vs `foxhole-vulns.json`.
2. **Kind-scoped policy** — `--policy` with `kinds: [secret]` and `fail_on: low`,
   plus a second stage with `kinds: [vuln]` and `fail_on: high`.
3. **Org packs** — `--policy-dir examples/policy-pack` merges YAML files
   (see [../policy-pack/](../policy-pack/)).

## Evidence packs

`--evidence` writes `foxhole-evidence/` with `manifest.json` (DB hash, `last_sync_at`,
policy fingerprint, image pin from `FOXHOLE_IMAGE` / `FOXHOLE_IMAGE_DIGEST`),
`policy.json`, `result.json`, `findings.sarif`, and `suppressions.json`.

## Diff-driven GitHub issues

Prefer `--github-diff` over `--github`: opens one issue per **new** finding vs the
last green scan, closes mapped issues when findings disappear, and attaches a
suppression YAML stub (plus triage drafts when `--triage` is set).

## Cosign verify

```bash
cosign verify \
  --certificate-identity-regexp='https://github.com/jasonflaherty/foxhole/\.github/workflows/publish-image\.yml@.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  "$FOXHOLE_IMAGE"
```

Air-gap: [../../docs/AIRGAP.md](../../docs/AIRGAP.md).

Prefer ticket + expiry over permanent `ignore:`:

```yaml
suppressions:
  - id: CVE-2024-0001
    until: "2026-12-01"
    ticket: "SEC-1234"
    reason: "Accepted risk pending vendor patch"
```

Expired suppressions no longer skip. Foxhole prints a warning when a suppression
is used.

## Patterns

1. **Shared DB** — Persist `.foxhole/foxhole.db` so PR jobs can run with `--offline` after a nightly `db update`.
2. **Offline PRs** — Warm the DB in a scheduled job; PR pipelines use `--offline`.
3. **Credentials** — Inject `FOXHOLE_NVD_API_KEY` and notify webhooks from Jenkins credentials.
4. **Notify** — Add `--teams` / `--email` / `--github` when those env vars are set.
5. **GHCR auth** — `docker login ghcr.io` if the package is private.

## Without Docker

```bash
foxhole db update
foxhole . --policy foxhole-policy.yaml --split-reports --max-db-age 720h --report console,json,sarif
```

## Related

- Policy example: [../policy.yaml](../policy.yaml)
- Policy packs: [../policy-pack/](../policy-pack/)
- Container pull: [../../docker/README.md](../../docker/README.md)
- Exit codes / flags: [../../README.md](../../README.md)
