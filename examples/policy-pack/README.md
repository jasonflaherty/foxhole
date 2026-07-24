# Org policy pack example

Merge with:

```bash
foxhole . --policy-dir examples/policy-pack --fail-on-kind secret --fail-on-kind vuln
# or rely on kinds from the YAML files:
foxhole . --policy-dir examples/policy-pack
```

| File | Effect |
|------|--------|
| [secrets-strict.yaml](secrets-strict.yaml) | Fail on secret findings at **low+** |
| [vulns-high.yaml](vulns-high.yaml) | Fail on vulns at **high+** |

`--policy-dir` merges all `*.yaml` / `*.yml`: **fail_on** = strictest (lowest threshold), **kinds** = union, **suppressions** / **ignore** = concatenated.

For separate gates (fail secrets harder than vulns), prefer two scan stages or `--split-reports` artifacts plus kind-scoped `--policy` runs — see [../jenkins/README.md](../jenkins/README.md).
