# Org policy pack — merge with `--policy-dir`

YAML packs are the portable unit (OPA-style gates for supply-chain CI, offline).

```bash
foxhole policy validate examples/policy-pack
foxhole . --policy-dir examples/policy-pack
```

| File | Effect |
|------|--------|
| [secrets-strict.yaml](secrets-strict.yaml) | Fail on **secret** findings at low+ |
| [vulns-high.yaml](vulns-high.yaml) | Fail on **vuln** findings at high+ |

Merge rules: **fail_on** = strictest (lowest threshold), **kinds** = union,
**suppressions** / **ignore** = concatenated.

For separate gates (fail secrets harder than vulns in different stages), use
`--fail-on-kind` / kind-scoped policies or `--split-reports` artifacts — see
[../jenkins/README.md](../jenkins/README.md).
