package evidence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/policy"
	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/version"
)

// SchemaVersion is the evidence pack manifest schema.
const SchemaVersion = "1.0.0"

// Input gathers data for an evidence pack.
type Input struct {
	Result       *scan.Result
	Policy       policy.Policy
	Decision     policy.Result
	Database     *db.DB
	MaxDBAge     string
	Image        string
	ImageDigest  string
	SplitReports bool
	OutDir       string
}

// Manifest is the audit summary for a gated scan.
type Manifest struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"tool_version"`
	Target        string    `json:"target"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	PolicyFailed  bool      `json:"policy_failed"`
	PolicyMessage string    `json:"policy_message,omitempty"`
	PolicyFP      string    `json:"policy_fingerprint"`
	Image         string    `json:"image,omitempty"`
	ImageDigest   string    `json:"image_digest,omitempty"`
	DB            DBInfo    `json:"db"`
	FindingCount  int       `json:"finding_count"`
	GeneratedAt   time.Time `json:"generated_at"`
}

// DBInfo captures vuln DB provenance for auditors.
type DBInfo struct {
	ProvidersSHA256 string `json:"providers_sha256,omitempty"`
	LastSyncAt      string `json:"last_sync_at,omitempty"`
	Age             string `json:"age,omitempty"`
	MaxDBAge        string `json:"max_db_age,omitempty"`
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Write creates an evidence directory with manifest, policy, result, SARIF, and suppressions.
func Write(ctx context.Context, in Input) (string, error) {
	dir := in.OutDir
	if dir == "" {
		dir = "foxhole-evidence"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	fp, err := policy.Fingerprint(in.Policy)
	if err != nil {
		return "", err
	}

	mani := Manifest{
		SchemaVersion: SchemaVersion,
		Tool:          "foxhole",
		ToolVersion:   version.Version,
		Target:        in.Result.Target,
		StartedAt:     in.Result.StartedAt,
		FinishedAt:    in.Result.FinishedAt,
		PolicyFailed:  in.Decision.Failed,
		PolicyMessage: in.Decision.Message,
		PolicyFP:      fp,
		Image:         in.Image,
		ImageDigest:   in.ImageDigest,
		FindingCount:  len(in.Result.Findings),
		GeneratedAt:   time.Now().UTC(),
		DB:            collectDB(ctx, in.Database, in.MaxDBAge),
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), mani); err != nil {
		return "", err
	}

	polOut := map[string]any{
		"fingerprint": fp,
		"policy":      in.Policy,
	}
	if err := writeJSON(filepath.Join(dir, "policy.json"), polOut); err != nil {
		return "", err
	}

	rf, err := os.Create(filepath.Join(dir, "result.json"))
	if err != nil {
		return "", err
	}
	err = (report.JSON{}).Write(rf, in.Result)
	_ = rf.Close()
	if err != nil {
		return "", err
	}

	sf, err := os.Create(filepath.Join(dir, "findings.sarif"))
	if err != nil {
		return "", err
	}
	err = (report.SARIF{}).Write(sf, in.Result)
	_ = sf.Close()
	if err != nil {
		return "", err
	}

	supp := map[string]any{
		"used":    in.Decision.UsedSupp,
		"expired": in.Decision.ExpiredSupp,
	}
	if err := writeJSON(filepath.Join(dir, "suppressions.json"), supp); err != nil {
		return "", err
	}

	if in.SplitReports {
		if err := report.WriteSplitJSON(in.Result, dir, discardWriter{}); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func collectDB(ctx context.Context, database *db.DB, maxAge string) DBInfo {
	info := DBInfo{MaxDBAge: maxAge}
	if database == nil {
		return info
	}
	if hash, ok, err := database.GetMetadata(ctx, "providers_sha256"); err == nil && ok {
		info.ProvidersSHA256 = hash
	}
	if synced, ok, err := database.LastSyncAt(ctx); err == nil && ok {
		info.LastSyncAt = synced.Format(time.RFC3339)
		info.Age = time.Since(synced).Round(time.Minute).String()
	}
	return info
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}
