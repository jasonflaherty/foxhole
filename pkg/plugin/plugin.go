// Package plugin defines the Foxhole extension SDK.
//
// Built-in vulnerability providers live in pkg/provider. This package
// provides the contracts for additional scanners, reporters, and notifiers
// that third parties can implement and register at process start.
package plugin

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Plugin is the base metadata contract for every extension.
type Plugin interface {
	Name() string
	Version() string
}

// Scanner discovers additional findings for a filesystem root.
type Scanner interface {
	Plugin
	Scan(ctx context.Context, root string) ([]scan.Finding, error)
}

// Reporter formats a scan result for a named output channel.
type Reporter interface {
	Plugin
	Format() string
	Write(w io.Writer, result *scan.Result) error
}

// Notifier delivers scan results to an external channel.
type Notifier interface {
	Plugin
	Notify(ctx context.Context, result *scan.Result) error
}

// Registry holds registered plugins by kind.
type Registry struct {
	mu        sync.RWMutex
	scanners  map[string]Scanner
	reporters map[string]Reporter
	notifiers map[string]Notifier
}

// NewRegistry creates an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners:  make(map[string]Scanner),
		reporters: make(map[string]Reporter),
		notifiers: make(map[string]Notifier),
	}
}

// RegisterScanner adds a scanner plugin.
func (r *Registry) RegisterScanner(p Scanner) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if name == "" {
		return fmt.Errorf("plugin: scanner name required")
	}
	if _, ok := r.scanners[name]; ok {
		return fmt.Errorf("plugin: scanner %q already registered", name)
	}
	r.scanners[name] = p
	return nil
}

// RegisterReporter adds a reporter plugin.
func (r *Registry) RegisterReporter(p Reporter) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if name == "" {
		return fmt.Errorf("plugin: reporter name required")
	}
	if _, ok := r.reporters[name]; ok {
		return fmt.Errorf("plugin: reporter %q already registered", name)
	}
	r.reporters[name] = p
	return nil
}

// RegisterNotifier adds a notifier plugin.
func (r *Registry) RegisterNotifier(p Notifier) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if name == "" {
		return fmt.Errorf("plugin: notifier name required")
	}
	if _, ok := r.notifiers[name]; ok {
		return fmt.Errorf("plugin: notifier %q already registered", name)
	}
	r.notifiers[name] = p
	return nil
}

// Scanners returns registered scanners.
func (r *Registry) Scanners() []Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Scanner, 0, len(r.scanners))
	for _, p := range r.scanners {
		out = append(out, p)
	}
	return out
}

// Reporters returns registered reporters.
func (r *Registry) Reporters() []Reporter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Reporter, 0, len(r.reporters))
	for _, p := range r.reporters {
		out = append(out, p)
	}
	return out
}

// Notifiers returns registered notifiers.
func (r *Registry) Notifiers() []Notifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Notifier, 0, len(r.notifiers))
	for _, p := range r.notifiers {
		out = append(out, p)
	}
	return out
}
