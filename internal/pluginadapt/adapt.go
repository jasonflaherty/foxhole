package pluginadapt

import (
	"context"

	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/pkg/plugin"
)

// Runner adapts pkg/plugin scanners into the scan engine.
type Runner struct {
	Reg *plugin.Registry
}

// ExtraFindings runs all registered plugin scanners.
func (r Runner) ExtraFindings(ctx context.Context, root string) ([]scan.Finding, error) {
	if r.Reg == nil {
		return nil, nil
	}
	var out []scan.Finding
	for _, s := range r.Reg.Scanners() {
		findings, err := s.Scan(ctx, root)
		if err != nil {
			return nil, err
		}
		out = append(out, findings...)
	}
	return out, nil
}
