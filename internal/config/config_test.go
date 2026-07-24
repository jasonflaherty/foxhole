package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DBPath == "" {
		t.Fatal("expected default db path")
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("log level = %q", cfg.LogLevel)
	}
}

func TestFromViperFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "foxhole.yaml")
	content := []byte("log_level: debug\noffline: true\ndb_path: /tmp/test.db\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	v := config.NewViper()
	v.AddConfigPath(dir)
	cfg, err := config.FromViper(v)
	if err != nil {
		t.Fatalf("FromViper: %v", err)
	}
	if !cfg.Offline {
		t.Fatal("expected offline true")
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("log level = %q", cfg.LogLevel)
	}
	if cfg.DBPath != "/tmp/test.db" {
		t.Fatalf("db path = %q", cfg.DBPath)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("FOXHOLE_LOG_LEVEL", "warn")
	v := config.NewViper()
	cfg, err := config.FromViper(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "warn" {
		t.Fatalf("log level = %q, want warn", cfg.LogLevel)
	}
}
