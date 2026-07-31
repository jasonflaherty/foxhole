# Air-gapped / offline Foxhole

Use this when CI cannot reach NVD/OSV on every job, but you still need a
**fresh, verifiable** vuln DB and audit evidence.

## Idea

```text
Networked builder                    Air-gapped agent
─────────────────                    ────────────────
db update  →  db export              cosign verify image
     │                                    │
     └──── bundle.tar.gz ─────────►  db import
                                          │
                                     scan --offline --max-db-age …
                                          │
                                     foxhole-evidence/
```

Tiny embedded seeds (`db update --offline`) are for **demos only**. Production
air-gap uses **exported DB bundles**.

## Steps

### 1. Networked builder (nightly / release)

```bash
foxhole db update
foxhole db export -o foxhole-db-$(date -u +%Y%m%d).tar.gz
# Optional: cosign sign-blob foxhole-db-….tar.gz
```

Or run one of:

| Workflow / pipeline | Role |
|---------------------|------|
| [nightly-db-bundle.yml](../.github/workflows/nightly-db-bundle.yml) | Scheduled online update → signed `.tar.gz` + rolling `db-bundle-nightly` release |
| [publish-db-bundle.yml](../.github/workflows/publish-db-bundle.yml) | Manual / GitHub Release attach |
| [Jenkinsfile.nightly](../examples/jenkins/Jenkinsfile.nightly) | Jenkins cron on a networked agent |

### 2. Mirror into the air gap

- CLI image: `ghcr.io/jasonflaherty/foxhole:<tag>` or `@sha256:…`
- DB bundle: the `.tar.gz` from step 1

### 3. Air-gapped agent

```bash
cosign verify \
  --certificate-identity-regexp='https://github.com/jasonflaherty/foxhole/\.github/workflows/publish-image\.yml@.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/jasonflaherty/foxhole:v0.4.1

foxhole db import ./foxhole-db-YYYYMMDD.tar.gz
foxhole . --offline --max-db-age 720h \
  --policy-dir ./policy-pack \
  --evidence --split-reports \
  --report console,json,sarif
```

`--max-db-age 720h` fails the job (**exit 1**) if the imported DB is older than 30 days.

Pipelines that encode this path:

| Workflow / pipeline | Role |
|---------------------|------|
| [airgap-offline-scan.yml](../.github/workflows/airgap-offline-scan.yml) | Actions demo: export → import → offline scan → stale-DB gate |
| [Jenkinsfile.airgap](../examples/jenkins/Jenkinsfile.airgap) | Jenkins PR/CI on offline agents (`copyArtifacts` from nightly) |
| [demo-db-bundle.yml](../.github/workflows/demo-db-bundle.yml) | Shorter Actions smoke for `db export`/`import` |

### 4. Keep the evidence pack

Archive `foxhole-evidence/` (DB hash, `last_sync_at`, policy fingerprint, SARIF,
suppressions) for auditors.

## Related

- [docker/README.md](../docker/README.md) — image pins + cosign
- [examples/jenkins/](../examples/jenkins/) — Jenkins + evidence artifacts
- [examples/policy-pack/](../examples/policy-pack/) — org policy YAML
- [README.md](../README.md) — full usage guide
