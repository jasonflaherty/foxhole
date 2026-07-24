package scan

import (
	"context"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/db"
)

func enrichFindings(ctx context.Context, store *db.DB, findings []Finding) {
	for i := range findings {
		f := &findings[i]
		if f.Kind != KindVuln {
			continue
		}
		cve := f.VulnID
		if !strings.HasPrefix(strings.ToUpper(cve), "CVE-") {
			if alias, err := store.ResolveCVEAlias(ctx, cve); err == nil && alias != "" {
				cve = alias
			} else {
				continue
			}
		}
		if ok, _ := store.InKEV(ctx, cve); ok {
			f.InKEV = true
			if strings.EqualFold(f.Severity, "medium") || strings.EqualFold(f.Severity, "low") || f.Severity == "" {
				f.Severity = "critical"
			}
		}
		if score, ok, _ := store.EPSSScore(ctx, cve); ok {
			f.EPSS = &score
		}
	}
}
