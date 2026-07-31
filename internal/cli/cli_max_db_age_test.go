package cli_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
)

func buildFoxhole(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "foxhole")
	build := exec.Command("go", "build", "-o", bin, "./cmd/foxhole")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestMaxDBAgeExitCode(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "foxhole.db")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module app\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	bin := buildFoxhole(t, dir)

	// No last_sync_at → exit 1
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	scan := exec.Command(bin, dir, "--db-path", dbPath, "--offline", "--secrets=false", "--eol=false",
		"--max-db-age", "1h", "--report", "console")
	var stderr bytes.Buffer
	scan.Stderr = &stderr
	err = scan.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for missing last_sync_at")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("exit = %v code want 1; stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("last_sync_at")) {
		t.Fatalf("stderr missing last_sync_at: %s", stderr.String())
	}

	// Seed DB (sets last_sync_at), then age it past max-db-age → exit 1
	seed := exec.Command(bin, "db", "update", dir, "--db-path", dbPath, "--offline")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}
	database, err = db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	if err := database.SetMetadata(context.Background(), "last_sync_at", old); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	scan2 := exec.Command(bin, dir, "--db-path", dbPath, "--offline", "--secrets=false", "--eol=false",
		"--max-db-age", "1h", "--report", "console")
	stderr.Reset()
	scan2.Stderr = &stderr
	err = scan2.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for stale DB")
	}
	exitErr, ok = err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("stale exit = %v want 1; stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("stale")) {
		t.Fatalf("stderr missing stale: %s", stderr.String())
	}

	// Fresh sync within window → exit 0
	seed2 := exec.Command(bin, "db", "update", dir, "--db-path", dbPath, "--offline")
	if out, err := seed2.CombinedOutput(); err != nil {
		t.Fatalf("reseed: %v\n%s", err, out)
	}
	scan3 := exec.Command(bin, dir, "--db-path", dbPath, "--offline", "--secrets=false", "--eol=false",
		"--max-db-age", "720h", "--report", "console")
	if out, err := scan3.CombinedOutput(); err != nil {
		t.Fatalf("fresh scan: %v\n%s", err, out)
	}
}
