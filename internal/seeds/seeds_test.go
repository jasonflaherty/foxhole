package seeds_test

import (
	"encoding/json"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/seeds"
)

func TestSeedsValidJSON(t *testing.T) {
	t.Parallel()
	var osv []map[string]any
	if err := json.Unmarshal(seeds.OSV, &osv); err != nil {
		t.Fatal(err)
	}
	if len(osv) == 0 {
		t.Fatal("empty osv seeds")
	}
	var nvd []map[string]any
	if err := json.Unmarshal(seeds.NVD, &nvd); err != nil {
		t.Fatal(err)
	}
	if len(nvd) == 0 {
		t.Fatal("empty nvd seeds")
	}
}
