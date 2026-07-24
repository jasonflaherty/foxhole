#!/usr/bin/env sh
# Build and run the offline Go demo with Docker or Podman.
set -eu
cd "$(dirname "$0")/.."

if command -v podman >/dev/null 2>&1; then
  ENGINE=podman
elif command -v docker >/dev/null 2>&1; then
  ENGINE=docker
else
  echo "error: install Docker or Podman, then re-run:" >&2
  echo "  ./docker/run-demo.sh" >&2
  exit 1
fi

echo "==> building with $ENGINE"
$ENGINE build -t foxhole-go-demo -f docker/Dockerfile.demo .

echo "==> running foxhole-go-demo"
exec $ENGINE run --rm foxhole-go-demo
