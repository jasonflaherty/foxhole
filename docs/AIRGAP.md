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

Or run [publish-db-bundle.yml](../.github/workflows/publish-db-bundle.yml).

### 2. Mirror into the air gap

- CLI image: `ghcr.io/jasonflaherty/foxhole:<tag>` or `@sha256:…`
- DB bundle: the `.tar.gz` from step 1

### 3. Air-gapped agent

```bash
cosign verify \
  --certificate-identity-regexp='https://github.com/jasonflaherty/foxhole/\.github/workflows/publish-image\.yml@.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/jasonflaherty/foxhole:v0.4.0

foxhole db import ./foxhole-db-YYYYMMDD.tar.gz
foxhole . --offline --max-db-age 720h \
  --policy-dir ./policy-pack \
  --evidence --split-reports \
  --report console,json,sarif
```

`--max-db-age 720h` fails the job (**exit 1**) if the imported DB is older than 30 days.

### 4. Keep the evidence pack

Archive `foxhole-evidence/` (DB hash, `last_sync_at`, policy fingerprint, SARIF,
suppressions) for auditors.

## CI demo

[demo-db-bundle.yml](../.github/workflows/demo-db-bundle.yml) exercises export →
import → offline scan → stale-DB fail in GitHub Actions.

## Related

- [docker/README.md](../docker/README.md) — image pins + cosign
- [examples/jenkins/](../examples/jenkins/) — Jenkins + evidence artifacts
- [examples/policy-pack/](../examples/policy-pack/) — org policy YAML
- [README.md](../README.md) — full usage guide
