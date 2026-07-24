# Air-gapped / offline Foxhole

Foxhole is designed so regulated and air-gapped CI can **prove** a workspace was
gated with fresh vulnerability data and approved policy — without SaaS telemetry.

## Happy path

1. **On a networked builder** (nightly or release pipeline):

```bash
foxhole db update
foxhole db export -o foxhole-db-$(date -u +%Y%m%d).tar.gz
# Optionally: cosign sign-blob foxhole-db-….tar.gz
```

2. **Mirror** into the air-gapped environment:

- Container image: `ghcr.io/jasonflaherty/foxhole:<tag>` or `@sha256:…` (verify with cosign)
- DB bundle: the `.tar.gz` from step 1

3. **On the air-gapped agent**:

```bash
# Verify image (identity pinned to this repo's publish workflow)
cosign verify \
  --certificate-identity-regexp='https://github.com/jasonflaherty/foxhole/\.github/workflows/publish-image\.yml@.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/jasonflaherty/foxhole:v0.2.0

foxhole db import ./foxhole-db-YYYYMMDD.tar.gz
foxhole . --offline --max-db-age 720h --policy-dir ./policy-pack \
  --evidence --split-reports --report console,json,sarif
```

4. **Archive evidence** for auditors: `foxhole-evidence/` (manifest with DB hash,
`last_sync_at`, policy fingerprint, SARIF, suppressions).

## What seeds are for

Embedded [internal/seeds](../internal/seeds) are **demo/bootstrap fixtures** for
`--offline` smoke tests. Production air-gap uses **exported DB bundles**, not seeds.

## Related

- Image pins + cosign: [docker/README.md](../docker/README.md), [examples/jenkins/](../examples/jenkins/)
- Policy packs: [examples/policy-pack/](../examples/policy-pack/)
- Evidence / triage / github-diff: [README.md](../README.md)
