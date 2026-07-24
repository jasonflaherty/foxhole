package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/diff"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/seeds"
	"github.com/jasonflaherty/foxhole/internal/version"
	"github.com/jasonflaherty/foxhole/pkg/provider/nvd"
	"github.com/jasonflaherty/foxhole/pkg/provider/osv"
)

// SeedPhase2 seeds secret/EOL data. Injected so the API package does not import cli.
type SeedPhase2 func(ctx context.Context, database *db.DB) error

// Server is the Foxhole REST API.
type Server struct {
	DB         *db.DB
	Cfg        *config.Config
	SeedPhase2 SeedPhase2
}

// NewRouter builds the Chi router.
func (s *Server) NewRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(5 * time.Minute))

	r.Get("/health", s.handleHealth)
	r.Get("/version", s.handleVersion)
	r.Get("/history", s.handleHistory)
	r.Post("/scan", s.handleScan)
	r.Post("/db/update", s.handleDBUpdate)
	r.Get("/", s.handleDashboard)
	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": version.Version})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	rows, err := s.DB.ListScanHistory(r.Context(), target, 50)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []db.ScanRecord{}
	}
	writeJSON(w, http.StatusOK, rows)
}

type scanRequest struct {
	Target  string `json:"target"`
	Offline bool   `json:"offline"`
	Secrets *bool  `json:"secrets"`
	EOL     *bool  `json:"eol"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && r.ContentLength != 0 {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if req.Target == "" {
		req.Target = "."
	}
	abs, err := filepath.Abs(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if s.SeedPhase2 != nil {
		if err := s.SeedPhase2(r.Context(), s.DB); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}

	offline := req.Offline || s.Cfg.Offline
	secrets := s.Cfg.Secrets
	eol := s.Cfg.EOL
	if req.Secrets != nil {
		secrets = *req.Secrets
	}
	if req.EOL != nil {
		eol = *req.EOL
	}

	histID, err := s.DB.StartScanHistory(r.Context(), abs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	osvProv := osv.New(s.DB, osv.WithOffline(offline))
	nvdProv := nvd.New(s.DB, nvd.WithOffline(offline), nvd.WithAPIKey(s.Cfg.NVDAPIKey))
	engine := scan.NewEngine(s.DB, osvProv, nvdProv).WithOptions(scan.EngineOptions{Secrets: secrets, EOL: eol})
	result, err := engine.Scan(r.Context(), abs)
	if err != nil {
		_ = s.DB.FinishScanHistory(r.Context(), histID, 0, "", "[]", "error")
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	snap, _ := diff.SnapshotJSON(result.Findings)
	_ = s.DB.FinishScanHistory(r.Context(), histID, len(result.Findings), "", snap, "ok")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDBUpdate(w http.ResponseWriter, r *http.Request) {
	if s.SeedPhase2 != nil {
		if err := s.SeedPhase2(r.Context(), s.DB); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	offline := s.Cfg.Offline || r.URL.Query().Get("offline") == "true"
	osvOpts := []osv.Option{osv.WithOffline(offline)}
	nvdOpts := []nvd.Option{nvd.WithOffline(offline), nvd.WithAPIKey(s.Cfg.NVDAPIKey)}
	if offline {
		osvOpts = append(osvOpts, osv.WithSeedAdvisories(seeds.OSV))
		nvdOpts = append(nvdOpts, nvd.WithSeedCVEs(seeds.NVD))
	}
	osvRes, err := osv.New(s.DB, osvOpts...).Update(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	nvdRes, err := nvd.New(s.DB, nvdOpts...).Update(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.DB.UpdateDBHash(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"osv": osvRes,
		"nvd": nvdRes,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
