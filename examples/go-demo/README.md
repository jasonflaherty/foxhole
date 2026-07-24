# go-demo

Minimal Go module that depends on `github.com/vulnerable/lib@v1.0.0`, which
matches Foxhole's offline OSV seed advisory.

```bash
./bin/foxhole db update examples/go-demo --offline
./bin/foxhole examples/go-demo --offline --secrets=false --eol=false
```

Also used by `./docker/run-demo.sh` (Docker or Podman).
