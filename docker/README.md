# Foxhole containers

Works with **Docker** or **Podman** (commands are interchangeable). Prefer Podman if both are installed — `./docker/run-demo.sh` picks it automatically.

## Images

| File | Image | Purpose |
|------|-------|---------|
| [Dockerfile.cli](Dockerfile.cli) | `foxhole` | CLI + `foxhole serve` |
| [Dockerfile.demo](Dockerfile.demo) | `foxhole-go-demo` | Offline scan of [examples/go-demo](../examples/go-demo) |

Data volume: `/var/lib/foxhole` (`FOXHOLE_DB_PATH=/var/lib/foxhole/foxhole.db`)

On SELinux hosts, add `:Z` to volume mounts (e.g. `-v foxhole-data:/var/lib/foxhole:Z`).

## Go demo (recommended)

From the repo root:

```bash
./docker/run-demo.sh

# or explicitly with Podman:
podman build -t foxhole-go-demo -f docker/Dockerfile.demo .
podman run --rm foxhole-go-demo
```

Expected output includes a **HIGH** finding for `github.com/vulnerable/lib@v1.0.0` (offline seed advisory).

## CLI image (Phase 1–4)

```bash
podman build -t foxhole -f docker/Dockerfile.cli .
```

### Seed DB + scan

```bash
podman run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD/examples/go-demo:/work:ro" \
  foxhole db update --offline

podman run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD/examples/go-demo:/work:ro" \
  foxhole /work --offline
```

### Archive, history, diff (Phase 3)

Use a writable mount for archive output and keep the same DB volume across runs:

```bash
mkdir -p "$PWD/archive"

podman run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD/examples/go-demo:/work:ro" \
  -v "$PWD/archive:/archive" \
  foxhole /work --offline --archive --archive-dir /archive

podman run --rm \
  -v foxhole-data:/var/lib/foxhole \
  foxhole history /work

podman run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD/examples/go-demo:/work:ro" \
  foxhole /work --offline

podman run --rm \
  -v foxhole-data:/var/lib/foxhole \
  foxhole diff last /work
```

History/`diff last` key off the **absolute target path inside the container** (`/work`), so remount the same path for consecutive scans.

### Notifications (Phase 3)

Pass env vars into the container:

```bash
podman run --rm \
  -v foxhole-data:/var/lib/foxhole \
  -v "$PWD/examples/go-demo:/work:ro" \
  -e FOXHOLE_TEAMS_WEBHOOK \
  -e FOXHOLE_GITHUB_TOKEN -e FOXHOLE_GITHUB_REPO \
  -e FOXHOLE_SMTP_HOST -e FOXHOLE_SMTP_PORT \
  -e FOXHOLE_SMTP_USER -e FOXHOLE_SMTP_PASS \
  -e FOXHOLE_EMAIL_FROM -e FOXHOLE_EMAIL_TO \
  foxhole /work --offline --teams   # and/or --github --email
```

### REST API + dashboard (Phase 4)

```bash
podman run --rm -p 8080:8080 \
  -v foxhole-data:/var/lib/foxhole \
  foxhole serve --addr :8080
```

Then open http://localhost:8080 (dashboard), or:

```bash
curl -s http://localhost:8080/health
curl -s -X POST http://localhost:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"/work","offline":true}'
```

To scan a host project via the API, also mount it (e.g. `-v "$PWD:/work:ro"`) and POST `"target":"/work"`.

## Online update (optional)

```bash
podman run --rm -v foxhole-data:/var/lib/foxhole foxhole db update
```

Requires network. Pass `--nvd-api-key` or `FOXHOLE_NVD_API_KEY` to raise NVD rate limits.

## Docker

Same commands with `docker` instead of `podman`.
