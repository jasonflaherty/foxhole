package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/pkg/provider/osv"
)

func TestEngineFindsSeededVuln(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()

	seed := []byte(`[{"id":"GO-2024-TEST","ecosystem":"Go","name":"github.com/vulnerable/lib","summary":"Test","severity":"HIGH","aliases":["CVE-2024-9999"],"fixed":"1.2.3"}]`)
	p := osv.New(database, osv.WithSeedAdvisories(seed), osv.WithOffline(true))
	if _, err := p.Update(context.Background()); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	mod := "module app\n\ngo 1.22\n\nrequire github.com/vulnerable/lib v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}

	engine := scan.NewEngine(database, p)
	result, err := engine.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Packages != 1 {
		t.Fatalf("packages = %d", result.Packages)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}
}
