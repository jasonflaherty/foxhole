package kev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jasonflaherty/foxhole/internal/seeds"
	"github.com/jasonflaherty/foxhole/pkg/provider"
)

const (
	providerID = "kev"
	catalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Store persists KEV rows.
type Store interface {
	UpsertKEV(ctx context.Context, cveID, vendor, product, dateAdded, dueDate, ransomware string) error
}

// Provider loads CISA KEV data.
type Provider struct {
	store   Store
	offline bool
	seed    []byte
	client  *http.Client
}

// Option configures the provider.
type Option func(*Provider)

func WithOffline(v bool) Option        { return func(p *Provider) { p.offline = v } }
func WithSeed(b []byte) Option         { return func(p *Provider) { p.seed = b } }
func WithClient(c *http.Client) Option { return func(p *Provider) { p.client = c } }

// New creates a KEV provider.
func New(store Store, opts ...Option) *Provider {
	p := &Provider{store: store, client: http.DefaultClient, seed: seeds.KEVJSON}
	for _, o := range opts {
		o(p)
	}
	return p
}

func (p *Provider) Metadata() provider.Metadata {
	return provider.Metadata{ID: providerID, Name: "CISA KEV", Description: "Known Exploited Vulnerabilities", Version: "1"}
}
func (p *Provider) Initialize(context.Context) error { return nil }
func (p *Provider) Verify(context.Context) error     { return nil }
func (p *Provider) Search(context.Context, provider.PackageQuery) ([]provider.Result, error) {
	return nil, nil
}

func (p *Provider) Update(ctx context.Context) (*provider.UpdateResult, error) {
	var raw []byte
	if p.offline {
		raw = p.seed
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := p.client.Do(req)
		if err != nil {
			// fall back to seed
			raw = p.seed
		} else {
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode >= 300 {
				raw = p.seed
			} else {
				raw, err = io.ReadAll(resp.Body)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("kev: empty catalog")
	}

	// Offline seed format is a flat array; CISA feed is {vulnerabilities:[...]}.
	type row struct {
		CVEID           string `json:"cveID"`
		CVEIDAlt        string `json:"cve_id"`
		VendorProject   string `json:"vendorProject"`
		VendorAlt       string `json:"vendor_project"`
		Product         string `json:"product"`
		DateAdded       string `json:"dateAdded"`
		DateAlt         string `json:"date_added"`
		DueDate         string `json:"dueDate"`
		DueAlt          string `json:"due_date"`
		KnownRansomware string `json:"knownRansomwareCampaignUse"`
		RansomAlt       string `json:"known_ransomware"`
	}
	var rows []row
	var feed struct {
		Vulnerabilities []row `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &feed); err == nil && len(feed.Vulnerabilities) > 0 {
		rows = feed.Vulnerabilities
	} else if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("kev parse: %w", err)
	}

	n := 0
	for _, r := range rows {
		cve := first(r.CVEID, r.CVEIDAlt)
		if cve == "" {
			continue
		}
		if err := p.store.UpsertKEV(ctx, cve, first(r.VendorProject, r.VendorAlt), r.Product,
			first(r.DateAdded, r.DateAlt), first(r.DueDate, r.DueAlt), first(r.KnownRansomware, r.RansomAlt)); err != nil {
			return nil, err
		}
		n++
	}
	sum := sha256.Sum256(raw)
	return &provider.UpdateResult{Records: n, ContentHash: hex.EncodeToString(sum[:]), UpdatedAt: time.Now().UTC()}, nil
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
