package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Suppression is a time-bounded accepted risk for a finding ID.
type Suppression struct {
	ID     string `yaml:"id" json:"id"`
	Until  string `yaml:"until" json:"until"` // YYYY-MM-DD or RFC3339; empty = permanent
	Ticket string `yaml:"ticket" json:"ticket"`
	Reason string `yaml:"reason" json:"reason"`
}

// Policy describes when a scan should fail.
type Policy struct {
	// ID is an optional pack identifier for evidence / audit.
	ID string `yaml:"id" json:"id,omitempty"`
	// Version is an optional pack version string.
	Version string `yaml:"version" json:"version,omitempty"`
	// FailOn is the minimum severity that fails the gate.
	FailOn string `yaml:"fail_on" json:"fail_on"`
	// Kinds limits which finding kinds are considered (empty = all).
	Kinds []string `yaml:"kinds" json:"kinds"`
	// Ignore is a set of finding IDs that never fail the gate (permanent).
	Ignore []string `yaml:"ignore" json:"ignore"`
	// Suppressions are time-bounded ignores (ticket + until recommended).
	Suppressions []Suppression `yaml:"suppressions" json:"suppressions"`
}

// LoadFile reads a single policy YAML file.
func LoadFile(path string) (Policy, error) {
	if path == "" {
		return Policy{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	return p, nil
}

// LoadDir merges all *.yaml / *.yml files in dir.
// fail_on uses the strictest severity; kinds are unioned; ignore/suppressions concatenated.
func LoadDir(dir string) (Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Policy{}, fmt.Errorf("policy dir: %w", err)
	}
	var merged Policy
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		p, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return Policy{}, err
		}
		merged = MergePolicies(merged, p)
	}
	return merged, nil
}

// MergePolicies combines two policies (b overlays onto a with union/strictest rules).
func MergePolicies(a, b Policy) Policy {
	out := a
	if b.ID != "" {
		out.ID = b.ID
	}
	if b.Version != "" {
		out.Version = b.Version
	}
	out.FailOn = strictestFailOn(a.FailOn, b.FailOn)
	out.Kinds = unionStrings(a.Kinds, b.Kinds)
	out.Ignore = append(append([]string{}, a.Ignore...), b.Ignore...)
	out.Suppressions = append(append([]Suppression{}, a.Suppressions...), b.Suppressions...)
	return out
}

func strictestFailOn(a, b string) string {
	na, nb := normalizeFailOn(a), normalizeFailOn(b)
	if na == "none" || na == "" {
		return b
	}
	if nb == "none" || nb == "" {
		return a
	}
	if na == "any" || nb == "any" {
		return "any"
	}
	// Lower severity threshold fails on more findings → stricter.
	if severityRank(na) <= severityRank(nb) {
		return na
	}
	return nb
}

func unionStrings(a, b []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, xs := range [][]string{a, b} {
		for _, s := range xs {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// ActiveSuppressions returns finding IDs suppressed as of now (and used IDs for warnings).
func ActiveSuppressions(p Policy, now time.Time) (active map[string]Suppression, expired []Suppression) {
	active = map[string]Suppression{}
	for _, id := range p.Ignore {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		active[id] = Suppression{ID: id, Reason: "legacy ignore"}
	}
	for _, s := range p.Suppressions {
		id := strings.TrimSpace(s.ID)
		if id == "" {
			continue
		}
		if s.Until == "" {
			active[id] = s
			continue
		}
		until, err := parseUntil(s.Until)
		if err != nil || now.After(until) {
			expired = append(expired, s)
			continue
		}
		active[id] = s
	}
	return active, expired
}

func parseUntil(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			// date-only: treat as end of that UTC day
			if layout == "2006-01-02" {
				return t.Add(24*time.Hour - time.Nanosecond).UTC(), nil
			}
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid until %q", s)
}
