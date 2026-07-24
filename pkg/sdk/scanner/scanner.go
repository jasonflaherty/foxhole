// Package scanner defines the Scanner SDK for Foxhole plugins.
// Scanners discover packages and dependencies in a filesystem.
package scanner

import (
	"context"
	"io/fs"
)

// Package represents a discovered package or dependency.
type Package struct {
	Ecosystem string // e.g., "npm", "pip", "cargo", "maven"
	Name      string
	Version   string
	Path      string // location in filesystem where discovered
}

// ScannerConfig holds configuration for a scanner.
type ScannerConfig struct {
	Enabled     bool                   `yaml:"enabled"`
	ExcludeDirs []string               `yaml:"exclude_dirs,omitempty"`
	Custom      map[string]interface{} `yaml:"custom,omitempty"`
}

// ScannerMetadata describes a scanner plugin.
type ScannerMetadata struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`        // e.g., "nodejs-npm"
	Version     string   `json:"version"`     // plugin version
	Description string   `json:"description"`
	Kind        string   `json:"kind"`        // "packager" or "custom"
	Languages   []string `json:"languages"`   // e.g., ["JavaScript", "TypeScript"]
	Author      string   `json:"author,omitempty"`
	Repository  string   `json:"repository,omitempty"`
}

// Scanner is the interface for package discovery plugins.
type Scanner interface {
	// Metadata returns plugin information.
	Metadata() ScannerMetadata

	// Detect checks if this scanner applies to a given path.
	// For packagers, this checks for manifest files (e.g., package.json).
	// Returns (detected, error).
	Detect(ctx context.Context, fsys fs.FS, path string) (bool, error)

	// Scan discovers packages starting from the given filesystem root.
	// Returns a list of discovered packages.
	Scan(ctx context.Context, fsys fs.FS, path string) ([]Package, error)

	// Configure applies settings to the scanner.
	Configure(ctx context.Context, cfg ScannerConfig) error

	// Close performs any cleanup (close files, connections, etc).
	Close(ctx context.Context) error
}
