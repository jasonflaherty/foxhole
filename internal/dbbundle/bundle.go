package dbbundle

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/version"
)

// BundleMeta is written as bundle.json inside the archive.
type BundleMeta struct {
	SchemaVersion   string `json:"schema_version"`
	Tool            string `json:"tool"`
	ToolVersion     string `json:"tool_version"`
	CreatedAt       string `json:"created_at"`
	LastSyncAt      string `json:"last_sync_at,omitempty"`
	ProvidersSHA256 string `json:"providers_sha256,omitempty"`
	DBFileSHA256    string `json:"db_file_sha256"`
	DBFileName      string `json:"db_file_name"`
}

const schemaVersion = "1.0.0"

// Export writes a gzip tar containing foxhole.db + bundle.json. Returns the output path.
func Export(ctx context.Context, database *db.DB, outPath string) (string, error) {
	if outPath == "" {
		outPath = fmt.Sprintf("foxhole-db-%s.tar.gz", time.Now().UTC().Format("20060102"))
	}
	dbPath := database.Path()
	sum, err := fileSHA256(dbPath)
	if err != nil {
		return "", err
	}
	meta := BundleMeta{
		SchemaVersion: schemaVersion,
		Tool:          "foxhole",
		ToolVersion:   version.Version,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		DBFileSHA256:  sum,
		DBFileName:    "foxhole.db",
	}
	if h, ok, _ := database.GetMetadata(ctx, "providers_sha256"); ok {
		meta.ProvidersSHA256 = h
	}
	if t, ok, _ := database.LastSyncAt(ctx); ok {
		meta.LastSyncAt = t.Format(time.RFC3339)
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", err
	}
	metaBytes = append(metaBytes, '\n')

	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	if err := writeTarFile(tw, "bundle.json", metaBytes); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		return "", err
	}
	dbFile, err := os.Open(dbPath)
	if err != nil {
		_ = tw.Close()
		_ = gw.Close()
		return "", err
	}
	st, err := dbFile.Stat()
	if err != nil {
		_ = dbFile.Close()
		_ = tw.Close()
		_ = gw.Close()
		return "", err
	}
	hdr := &tar.Header{Name: "foxhole.db", Mode: 0o644, Size: st.Size(), ModTime: st.ModTime()}
	if err := tw.WriteHeader(hdr); err != nil {
		_ = dbFile.Close()
		_ = tw.Close()
		_ = gw.Close()
		return "", err
	}
	if _, err := io.Copy(tw, dbFile); err != nil {
		_ = dbFile.Close()
		_ = tw.Close()
		_ = gw.Close()
		return "", err
	}
	_ = dbFile.Close()
	if err := tw.Close(); err != nil {
		_ = gw.Close()
		return "", err
	}
	if err := gw.Close(); err != nil {
		return "", err
	}
	return outPath, nil
}

// Import extracts a bundle into destDBPath after verifying digests.
func Import(bundlePath, destDBPath string) (*BundleMeta, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)

	var meta BundleMeta
	var dbData []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch filepath.Base(hdr.Name) {
		case "bundle.json":
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(b, &meta); err != nil {
				return nil, err
			}
		case "foxhole.db":
			dbData, err = io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
		}
	}
	if len(dbData) == 0 {
		return nil, fmt.Errorf("bundle missing foxhole.db")
	}
	if meta.DBFileSHA256 == "" {
		return nil, fmt.Errorf("bundle missing db_file_sha256")
	}
	sum := sha256.Sum256(dbData)
	got := hex.EncodeToString(sum[:])
	if got != meta.DBFileSHA256 {
		return nil, fmt.Errorf("db digest mismatch: got %s want %s", got, meta.DBFileSHA256)
	}
	if err := os.MkdirAll(filepath.Dir(destDBPath), 0o755); err != nil {
		return nil, err
	}
	tmp := destDBPath + ".tmp"
	if err := os.WriteFile(tmp, dbData, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, destDBPath); err != nil {
		return nil, err
	}
	// Re-open to apply migrations and restore metadata timestamps from bundle.
	database, err := db.Open(destDBPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()
	if meta.ProvidersSHA256 != "" {
		_ = database.SetMetadata(ctx, "providers_sha256", meta.ProvidersSHA256)
	}
	if meta.LastSyncAt != "" {
		_ = database.SetMetadata(ctx, "last_sync_at", meta.LastSyncAt)
	}
	return &meta, nil
}

func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: time.Now().UTC()}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
