package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/api"
	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/seeds"
	"github.com/jasonflaherty/foxhole/pkg/provider/osv"
)

func TestHealthAndVersion(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	srv := &api.Server{DB: database, Cfg: &config.Config{Secrets: true, EOL: true}}
	h := srv.NewRouter()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("health status = %d", rr.Code)
	}
	var health map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &health)
	if health["status"] != "ok" {
		t.Fatalf("health = %#v", health)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("version status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct == "" || rr.Body.Len() == 0 {
		t.Fatalf("dashboard empty or missing content-type: %q", ct)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/history", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("history status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScanAndHistory(t *testing.T) {
	dir := t.TempDir()
	mod := "module app\n\ngo 1.22\n\nrequire github.com/vulnerable/lib v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}

	database, err := db.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	osvProv := osv.New(database, osv.WithOffline(true), osv.WithSeedAdvisories(seeds.OSV))
	if _, err := osvProv.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	seedFn := func(ctx context.Context, database *db.DB) error {
		secretRules, err := seeds.SecretRules()
		if err != nil {
			return err
		}
		eolRecords, err := seeds.EOLRecords()
		if err != nil {
			return err
		}
		return database.EnsurePhase2Seeds(ctx, secretRules, eolRecords)
	}

	srv := &api.Server{
		DB:         database,
		Cfg:        &config.Config{Secrets: false, EOL: false, Offline: true},
		SeedPhase2: seedFn,
	}
	h := srv.NewRouter()

	body, _ := json.Marshal(map[string]any{
		"target":  dir,
		"offline": true,
		"secrets": false,
		"eol":     false,
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("scan status = %d body=%s", rr.Code, rr.Body.String())
	}
	var scanEnvelope map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &scanEnvelope); err != nil {
		t.Fatal(err)
	}
	if scanEnvelope["schema_version"] != "1.0.0" || scanEnvelope["tool"] != "foxhole" {
		t.Fatalf("expected schema envelope, got %#v", scanEnvelope)
	}
	scanResult, _ := scanEnvelope["result"].(map[string]any)
	findings, _ := scanResult["findings"].([]any)
	if len(findings) < 1 {
		t.Fatalf("expected vuln findings, got %#v", scanEnvelope)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/history", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("history status = %d", rr.Code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 1 {
		t.Fatalf("expected history row, body=%s", rr.Body.String())
	}
}

func TestAPITokenAuth(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	srv := &api.Server{DB: database, Cfg: &config.Config{APIToken: "secret-token", Secrets: true, EOL: true}}
	h := srv.NewRouter()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("health should stay public, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/history", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("history without token = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/history", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("history with token = %d body=%s", rr.Code, rr.Body.String())
	}
}
