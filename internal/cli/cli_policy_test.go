package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFailOnExitCode(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "foxhole.db")
	mod := "module app\n\ngo 1.20\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	// Seed an obvious high severity via demo.env secret pattern isn't needed —
	// EOL from go 1.20 is typically high in seeds. Also write a fake AWS key for secret.
	env := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if err := os.WriteFile(filepath.Join(dir, "demo.env"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(dir, "foxhole")
	build := exec.Command("go", "build", "-o", bin, "./cmd/foxhole")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	seed := exec.Command(bin, "db", "update", dir, "--db-path", dbPath, "--offline")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed: %v\n%s", err, out)
	}

	scan := exec.Command(bin, dir, "--db-path", dbPath, "--offline", "--fail-on", "high", "--report", "console")
	var stdout, stderr bytes.Buffer
	scan.Stdout = &stdout
	scan.Stderr = &stderr
	err := scan.Run()
	if err == nil {
		t.Fatalf("expected non-zero exit; stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("err type %T: %v", err, err)
	}
	if code := exitErr.ExitCode(); code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("policy failed")) {
		t.Fatalf("stderr missing policy failed: %s", stderr.String())
	}
}
