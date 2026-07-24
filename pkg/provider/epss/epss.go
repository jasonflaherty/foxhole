package epss

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jasonflaherty/foxhole/internal/seeds"
	"github.com/jasonflaherty/foxhole/pkg/provider"
)

const providerID = "epss"

// Store persists EPSS scores.
type Store interface {
	UpsertEPSS(ctx context.Context, cveID string, score, percentile float64) error
}

// Provider loads EPSS scores (seed-first; full CSV feed can be added later).
type Provider struct {
	store   Store
	offline bool
	seed    []byte
}

type Option func(*Provider)

func WithOffline(v bool) Option { return func(p *Provider) { p.offline = v } }
func WithSeed(b []byte) Option  { return func(p *Provider) { p.seed = b } }

func New(store Store, opts ...Option) *Provider {
	p := &Provider{store: store, seed: seeds.EPSSJSON, offline: true}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *Provider) Metadata() provider.Metadata {
	return provider.Metadata{ID: providerID, Name: "EPSS", Description: "Exploit Prediction Scoring System", Version: "1"}
}
func (p *Provider) Initialize(context.Context) error { return nil }
func (p *Provider) Verify(context.Context) error     { return nil }
func (p *Provider) Search(context.Context, provider.PackageQuery) ([]provider.Result, error) {
	return nil, nil
}

func (p *Provider) Update(ctx context.Context) (*provider.UpdateResult, error) {
	raw := p.seed
	if len(raw) == 0 {
		return nil, fmt.Errorf("epss: empty seed")
	}
	var rows []struct {
		CVEID      string  `json:"cve_id"`
		Score      float64 `json:"score"`
		Percentile float64 `json:"percentile"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		if err := p.store.UpsertEPSS(ctx, r.CVEID, r.Score, r.Percentile); err != nil {
			return nil, err
		}
	}
	sum := sha256.Sum256(raw)
	return &provider.UpdateResult{Records: len(rows), ContentHash: hex.EncodeToString(sum[:]), UpdatedAt: time.Now().UTC()}, nil
}
