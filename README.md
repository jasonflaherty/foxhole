# Foxhole

Offline-first, open-source software supply chain security scanner.

Foxhole combines vulnerability (NVD/OSV), secret, EOL, SBOM, license, and
misconfiguration scanning with reporting and notifications. Phase 1 ships the
CLI, SQLite database, NVD/OSV providers, and filesystem dependency scanning.

## Quick start

```bash
go install github.com/jasonflaherty/foxhole/cmd/foxhole@latest

# Update local vulnerability database (requires network)
foxhole db update

# Scan the current directory (works offline against local DB)
foxhole .
foxhole . --offline
```

## Configuration

Precedence: **CLI flags > environment variables (`FOXHOLE_*`) > `foxhole.yaml`**

See [examples/foxhole.yaml](examples/foxhole.yaml).

| Flag / env | Description |
|---|---|
| `--db-path` / `FOXHOLE_DB_PATH` | SQLite path (default `~/.foxhole/foxhole.db`) |
| `--offline` / `FOXHOLE_OFFLINE` | Disable network access |
| `--log-level` / `FOXHOLE_LOG_LEVEL` | Zap log level |
| `--nvd-api-key` / `FOXHOLE_NVD_API_KEY` | Optional NVD API key |

## CLI

```bash
foxhole .                     # scan path
foxhole db update             # refresh NVD + OSV into SQLite
foxhole db verify             # verify provider SHA256 hashes
foxhole version
```

## Development

```bash
go test ./...
golangci-lint run
go build -o bin/foxhole ./cmd/foxhole
```

## Architecture

See [docs/Foxhole_Design_Book.md](docs/Foxhole_Design_Book.md).

## License

MIT — see [LICENSE](LICENSE).
