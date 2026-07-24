package provider

import (
	"context"
	"fmt"
	"time"
)

// PackageQuery describes a package to look up.
type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

// Result is a vulnerability finding from a provider search.
type Result struct {
	ID        string
	Aliases   []string
	Summary   string
	Severity  string
	CVSSScore *float64
	Fixed     string
	Source    string
	RawJSON   string
}

// Metadata describes a provider.
type Metadata struct {
	ID          string
	Name        string
	Description string
	Version     string
}

// UpdateResult summarizes a provider update.
type UpdateResult struct {
	Records     int
	ContentHash string
	UpdatedAt   time.Time
}

// Provider is the plugin contract for vulnerability data sources.
type Provider interface {
	Metadata() Metadata
	Initialize(ctx context.Context) error
	Update(ctx context.Context) (*UpdateResult, error)
	Verify(ctx context.Context) error
	Search(ctx context.Context, q PackageQuery) ([]Result, error)
}

// Registry holds named providers.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// Register adds a provider.
func (r *Registry) Register(p Provider) {
	meta := p.Metadata()
	r.providers[meta.ID] = p
}

// Get returns a provider by id.
func (r *Registry) Get(id string) (Provider, bool) {
	p, ok := r.providers[id]
	return p, ok
}

// All returns all registered providers.
func (r *Registry) All() []Provider {
	out := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	return out
}

// UpdateAll runs Update on every provider.
func (r *Registry) UpdateAll(ctx context.Context) (map[string]*UpdateResult, error) {
	results := make(map[string]*UpdateResult, len(r.providers))
	for id, p := range r.providers {
		if err := p.Initialize(ctx); err != nil {
			return results, fmt.Errorf("%s initialize: %w", id, err)
		}
		res, err := p.Update(ctx)
		if err != nil {
			return results, fmt.Errorf("%s update: %w", id, err)
		}
		results[id] = res
	}
	return results, nil
}
