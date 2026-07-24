// Package provider defines the Provider SDK for Foxhole plugins.
// Providers supply vulnerability or security data sources.
package provider

import (
	"context"
	"time"
)

// PackageQuery describes a package to look up.
type PackageQuery struct {
	Ecosystem string // npm, pip, cargo, maven, etc.
	Name      string
	Version   string
}

// Advisory is a vulnerability or advisory record.
type Advisory struct {
	ID        string     // unique identifier (CVE, OSV ID, etc.)
	Aliases   []string   // alternate IDs
	Summary   string     // description
	Severity  string     // LOW, MEDIUM, HIGH, CRITICAL
	CVSSScore *float64   // CVSS v3 base score
	Fixed     string     // fixed version or status
	Published *time.Time // publication date
	Modified  *time.Time // last modification date
	Source    string     // data source (NVD, OSV, GHSA, etc.)
	RawJSON   string     // original data for archival
}

// UpdateResult summarizes a provider update.
type UpdateResult struct {
	Records     int       // total records in provider
	ContentHash string    // SHA256 of content for integrity checking
	UpdatedAt   time.Time // when update completed
}

// ProviderMetadata describes a provider plugin.
type ProviderMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`          // e.g., "nvd-provider"
	Version     string `json:"version"`       // plugin version
	Description string `json:"description"`
	DataSource  string `json:"data_source"`   // e.g., "NVD", "OSV"
	RefreshAge  int    `json:"refresh_age"`   // max age in hours before stale
	Offline     bool   `json:"offline"`       // can operate without network
	Author      string `json:"author,omitempty"`
	Repository  string `json:"repository,omitempty"`
}

// ProviderConfig holds configuration for a provider.
type ProviderConfig struct {
	Enabled   bool                   `yaml:"enabled"`
	Endpoint  string                 `yaml:"endpoint,omitempty"`    // API URL
	Auth      map[string]string      `yaml:"auth,omitempty"`        // API keys, tokens
	CachePath string                 `yaml:"cache_path,omitempty"`  // local cache
	Custom    map[string]interface{} `yaml:"custom,omitempty"`      // provider-specific
}

// Provider is the interface for vulnerability data sources.
type Provider interface {
	// Metadata returns provider information.
	Metadata() ProviderMetadata

	// Initialize prepares the provider (load config, check connectivity, etc).
	Initialize(ctx context.Context, cfg ProviderConfig) error

	// Update refreshes the provider's data from the source.
	// Returns summary info or error.
	Update(ctx context.Context) (*UpdateResult, error)

	// Verify checks provider integrity (e.g., content hash, record count).
	Verify(ctx context.Context) error

	// Search queries for advisories matching a package.
	// Returns empty slice if no matches found.
	Search(ctx context.Context, q PackageQuery) ([]Advisory, error)

	// Close performs cleanup.
	Close(ctx context.Context) error
}
