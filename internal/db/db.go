package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

const driverName = "sqlite"

// DB wraps a SQLite connection used by Foxhole.
type DB struct {
	sql  *sql.DB
	path string
}

// Open opens (or creates) the Foxhole SQLite database and runs migrations.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", path)
	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	d := &DB{sql: sqlDB, path: path}
	if err := d.Migrate(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// SQL returns the underlying *sql.DB.
func (d *DB) SQL() *sql.DB {
	return d.sql
}

// Path returns the database file path.
func (d *DB) Path() string {
	return d.path
}

// Close closes the database.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// Migrate applies embedded goose migrations.
func (d *DB) Migrate() error {
	goose.SetBaseFS(migrationsFS)
	goose.SetLogger(log.New(io.Discard, "", 0))
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	if err := goose.Up(d.sql, "migrations"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// SetMetadata stores a metadata key/value pair.
func (d *DB) SetMetadata(ctx context.Context, key, value string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO metadata (key, value, updated_at) VALUES (?, ?, datetime('now'))
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value)
	return err
}

// GetMetadata returns a metadata value.
func (d *DB) GetMetadata(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := d.sql.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// UpsertProvider records provider sync metadata including content SHA256.
func (d *DB) UpsertProvider(ctx context.Context, id, name, version, sha256sum, status string) error {
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO providers (id, name, version, last_updated, content_sha256, status)
		VALUES (?, ?, ?, datetime('now'), ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			version = excluded.version,
			last_updated = excluded.last_updated,
			content_sha256 = excluded.content_sha256,
			status = excluded.status
	`, id, name, version, sha256sum, status)
	return err
}

// ProviderSHA256 returns the stored content hash for a provider.
func (d *DB) ProviderSHA256(ctx context.Context, id string) (string, bool, error) {
	var hash string
	err := d.sql.QueryRowContext(ctx, `SELECT content_sha256 FROM providers WHERE id = ?`, id).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// LastProviderUpdate returns when a provider was last updated.
func (d *DB) LastProviderUpdate(ctx context.Context, id string) (time.Time, bool, error) {
	var raw sql.NullString
	err := d.sql.QueryRowContext(ctx, `SELECT last_updated FROM providers WHERE id = ?`, id).Scan(&raw)
	if err == sql.ErrNoRows || !raw.Valid {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse("2006-01-02 15:04:05", raw.String)
	if err != nil {
		t, err = time.Parse(time.RFC3339, raw.String)
		if err != nil {
			return time.Time{}, false, err
		}
	}
	return t, true, nil
}

// FileSHA256 computes the SHA256 of a file on disk.
func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(data), nil
}

// SHA256Bytes returns the hex-encoded SHA256 of b.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IntegrityOK runs SQLite quick_check. Provider payload SHA256 is verified separately
// via Provider.Verify / ProviderSHA256.
func (d *DB) IntegrityOK(ctx context.Context) (bool, error) {
	var result string
	if err := d.sql.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&result); err != nil {
		return false, err
	}
	return result == "ok", nil
}

// UpdateDBHash records a content fingerprint of provider hashes after a sync.
func (d *DB) UpdateDBHash(ctx context.Context) error {
	rows, err := d.sql.QueryContext(ctx, `SELECT id || ':' || content_sha256 FROM providers ORDER BY id`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var parts []byte
	for rows.Next() {
		var part string
		if err := rows.Scan(&part); err != nil {
			return err
		}
		parts = append(parts, part...)
		parts = append(parts, '\n')
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return d.SetMetadata(ctx, "providers_sha256", SHA256Bytes(parts))
}
