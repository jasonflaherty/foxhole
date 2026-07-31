package seeds

import (
	_ "embed"
	"encoding/json"

	"github.com/jasonflaherty/foxhole/internal/db"
)

// Curated high-confidence token/key patterns (AWS, GCP, Azure, GitHub, JWT,
// PEM/PGP, Slack, Stripe, …). Prefer branded prefixes over generic entropy.
//
//go:embed secrets.json
var SecretsJSON []byte

//go:embed eol.json
var EOLJSON []byte

// SecretRules returns built-in secret detection rules.
func SecretRules() ([]db.SecretRule, error) {
	var raw []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Pattern  string `json:"pattern"`
		Severity string `json:"severity"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.Unmarshal(SecretsJSON, &raw); err != nil {
		return nil, err
	}
	out := make([]db.SecretRule, 0, len(raw))
	for _, r := range raw {
		out = append(out, db.SecretRule{
			ID: r.ID, Name: r.Name, Pattern: r.Pattern, Severity: r.Severity, Enabled: r.Enabled,
		})
	}
	return out, nil
}

// EOLRecords returns built-in EOL cycles.
func EOLRecords() ([]db.EOLRecord, error) {
	var out []db.EOLRecord
	if err := json.Unmarshal(EOLJSON, &out); err != nil {
		return nil, err
	}
	return out, nil
}
