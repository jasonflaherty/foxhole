#!/bin/sh
set -eu

DB_PATH="${FOXHOLE_DB_PATH:-/var/lib/foxhole/foxhole.db}"
TARGET="${1:-/demo}"

echo "==> foxhole db update (offline seeds)"
foxhole db update --db-path "$DB_PATH" --offline

echo "==> foxhole scan: $TARGET"
exec foxhole "$TARGET" --db-path "$DB_PATH" --offline
