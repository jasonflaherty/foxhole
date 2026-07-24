package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/api"
	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
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
