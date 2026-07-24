# Foxhole containers

Works with **Docker** or **Podman** (commands are interchangeable).

## Images

| File | Image | Purpose |
|------|-------|---------|
| [Dockerfile.cli](Dockerfile.cli) | `foxhole` | CLI scanner |
| [Dockerfile.demo](Dockerfile.demo) | `foxhole-go-demo` | Offline scan of [examples/go-demo](../examples/go-demo) |

Data volume: `/var/lib/foxhole`

## Go demo (recommended)

From the repo root:

```bash
./docker/run-demo.sh

# or explicitly:
docker build -t foxhole-go-demo -f docker/Dockerfile.demo .
docker run --rm foxhole-go-demo

# Podman
podman build -t foxhole-go-demo -f docker/Dockerfile.demo .
podman run --rm foxhole-go-demo
```

Expected output includes a **HIGH** finding for `github.com/vulnerable/lib@v1.0.0` (offline seed advisory).

## CLI image

```bash
docker build -t foxhole -f docker/Dockerfile.cli .
# or: podman build -t foxhole -f docker/Dockerfile.cli .

# Seed DB + scan a mounted project
docker run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD/examples/go-demo:/work:ro" \
  foxhole db update --offline

docker run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD/examples/go-demo:/work:ro" \
  foxhole /work --offline
```

Podman equivalent (replace `docker` with `podman`; use `-v foxhole-data:/var/lib/foxhole:Z` on SELinux hosts if needed).

## Online update (optional)

```bash
docker run --rm -v foxhole-data:/var/lib/foxhole foxhole db update
```

Requires network. Pass `--nvd-api-key` or `FOXHOLE_NVD_API_KEY` to raise NVD rate limits.
