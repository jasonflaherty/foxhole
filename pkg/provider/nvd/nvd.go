package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/pkg/provider"
)

const (
	providerID   = "nvd"
	providerName = "NVD"
	apiBase      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

// Store is the persistence surface required by the NVD provider.
type Store interface {
	UpsertCVE(ctx context.Context, id, source, summary, severity string, cvss *float64, published, modified, rawJSON string) error
	UpsertAlias(ctx context.Context, alias, vulnID string) error
	UpsertProvider(ctx context.Context, id, name, version, sha256sum, status string) error
	ProviderSHA256(ctx context.Context, id string) (string, bool, error)
	SearchCVE(ctx context.Context, id string) (*db.Finding, error)
	SetMetadata(ctx context.Context, key, value string) error
}

// HTTPDoer abstracts HTTP for tests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider implements provider.Provider for NVD.
type Provider struct {
	store    Store
	client   HTTPDoer
	apiKey   string
	offline  bool
	lastHash string
	seedCVEs []seedCVE
	// recentDays limits online sync window (default 7).
	recentDays int
}

type seedCVE struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Severity  string   `json:"severity"`
	CVSSScore *float64 `json:"cvss_score"`
}

// Option configures the NVD provider.
type Option func(*Provider)

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(c HTTPDoer) Option {
	return func(p *Provider) { p.client = c }
}

// WithAPIKey sets an optional NVD API key.
func WithAPIKey(key string) Option {
	return func(p *Provider) { p.apiKey = key }
}

// WithOffline disables network calls.
func WithOffline(offline bool) Option {
	return func(p *Provider) { p.offline = offline }
}

// WithRecentDays sets how many days of NVD modifications to pull.
func WithRecentDays(days int) Option {
	return func(p *Provider) { p.recentDays = days }
}

// WithSeedCVEs injects fixture CVEs (tests / offline bootstrap).
func WithSeedCVEs(raw []byte) Option {
	return func(p *Provider) {
		var items []seedCVE
		if err := json.Unmarshal(raw, &items); err == nil {
			p.seedCVEs = items
		}
	}
}

// New creates an NVD provider.
func New(store Store, opts ...Option) *Provider {
	p := &Provider{
		store:      store,
		client:     http.DefaultClient,
		recentDays: 7,
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.recentDays <= 0 {
		p.recentDays = 7
	}
	return p
}

// Metadata returns provider metadata.
func (p *Provider) Metadata() provider.Metadata {
	return provider.Metadata{
		ID:          providerID,
		Name:        providerName,
		Description: "National Vulnerability Database",
		Version:     "2.0",
	}
}

// Initialize prepares the provider.
func (p *Provider) Initialize(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Update refreshes NVD CVE data.
func (p *Provider) Update(ctx context.Context) (*provider.UpdateResult, error) {
	var (
		count int
		hash  string
		err   error
	)

	if len(p.seedCVEs) > 0 {
		count, hash, err = p.loadSeeds(ctx)
	} else if p.offline {
		return nil, fmt.Errorf("nvd: offline update requires seed data or an existing database")
	} else {
		count, hash, err = p.fetchRecent(ctx)
	}
	if err != nil {
		_ = p.store.UpsertProvider(ctx, providerID, providerName, "2.0", "", "error")
		return nil, err
	}
	if err := p.store.UpsertProvider(ctx, providerID, providerName, "2.0", hash, "ok"); err != nil {
		return nil, err
	}
	_ = p.store.SetMetadata(ctx, "nvd_last_update", time.Now().UTC().Format(time.RFC3339))
	p.lastHash = hash
	return &provider.UpdateResult{Records: count, ContentHash: hash, UpdatedAt: time.Now().UTC()}, nil
}

// Verify checks stored content hash.
func (p *Provider) Verify(ctx context.Context) error {
	stored, ok, err := p.store.ProviderSHA256(ctx, providerID)
	if err != nil {
		return err
	}
	if !ok || stored == "" {
		return fmt.Errorf("nvd: missing content hash; run foxhole db update")
	}
	if p.lastHash != "" && p.lastHash != stored {
		return fmt.Errorf("nvd: content hash mismatch")
	}
	return nil
}

// Search looks up a CVE id in the local database. Package queries return empty
// (NVD package CPE matching lands in a later phase); OSV covers package search.
func (p *Provider) Search(ctx context.Context, q provider.PackageQuery) ([]provider.Result, error) {
	if q.Name == "" {
		return nil, nil
	}
	// Allow direct CVE id lookups via Name field when ecosystem is "cve".
	if strings.EqualFold(q.Ecosystem, "cve") || strings.HasPrefix(strings.ToUpper(q.Name), "CVE-") {
		f, err := p.store.SearchCVE(ctx, q.Name)
		if err != nil || f == nil {
			return nil, err
		}
		var score *float64
		if f.CVSSScore.Valid {
			v := f.CVSSScore.Float64
			score = &v
		}
		return []provider.Result{{
			ID:        f.VulnID,
			Summary:   f.Summary,
			Severity:  f.Severity,
			CVSSScore: score,
			Source:    providerID,
		}}, nil
	}
	return nil, nil
}

func (p *Provider) loadSeeds(ctx context.Context) (int, string, error) {
	raw, _ := json.Marshal(p.seedCVEs)
	hash := db.SHA256Bytes(raw)
	for _, c := range p.seedCVEs {
		if err := p.store.UpsertCVE(ctx, c.ID, providerID, c.Summary, c.Severity, c.CVSSScore, "", "", ""); err != nil {
			return 0, "", err
		}
		_ = p.store.UpsertAlias(ctx, c.ID, c.ID)
	}
	return len(p.seedCVEs), hash, nil
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (p *Provider) fetchRecent(ctx context.Context) (int, string, error) {
	end := time.Now().UTC()
	start := end.Add(-time.Duration(p.recentDays) * 24 * time.Hour)

	u, err := url.Parse(apiBase)
	if err != nil {
		return 0, "", err
	}
	q := u.Query()
	q.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000"))
	q.Set("lastModEndDate", end.Format("2006-01-02T15:04:05.000"))
	q.Set("resultsPerPage", "200")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, "", err
	}
	if p.apiKey != "" {
		req.Header.Set("apiKey", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("nvd api: status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var parsed nvdResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, "", err
	}
	hash := db.SHA256Bytes(body)
	count := 0
	for _, item := range parsed.Vulnerabilities {
		cve := item.CVE
		summary := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				summary = d.Value
				break
			}
		}
		var score *float64
		severity := ""
		if len(cve.Metrics.CvssMetricV31) > 0 {
			s := cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			score = &s
			severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(cve.Metrics.CvssMetricV30) > 0 {
			s := cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
			score = &s
			severity = cve.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
		}
		raw, _ := json.Marshal(item)
		if err := p.store.UpsertCVE(ctx, cve.ID, providerID, summary, severity, score, cve.Published, cve.LastModified, string(raw)); err != nil {
			return 0, "", err
		}
		_ = p.store.UpsertAlias(ctx, cve.ID, cve.ID)
		count++
	}
	return count, hash, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
