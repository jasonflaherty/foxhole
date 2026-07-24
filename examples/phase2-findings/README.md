# Phase 2 findings demo

Tiny fixture used by GitHub Actions to show **secret** and **EOL** findings.

| File | Purpose |
|------|---------|
| `go.mod` | Pins `go 1.20` (seeded as end-of-life) |
| `demo.env` | Contains AWS's documented example access key ID |

```bash
go build -o bin/foxhole ./cmd/foxhole
./bin/foxhole db update examples/phase2-findings --offline
./bin/foxhole examples/phase2-findings --offline --report console,json
```
