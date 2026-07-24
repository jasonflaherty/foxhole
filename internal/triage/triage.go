package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/remediate"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"gopkg.in/yaml.v3"
)

// Group clusters related findings for triage.
type Group struct {
	Key        string         `json:"key"`
	Title      string         `json:"title"`
	FindingIDs []string       `json:"finding_ids"`
	Findings   []scan.Finding `json:"findings,omitempty"`
	Narrative  string         `json:"narrative"`
	Actions    []string       `json:"actions"`
	IssueDraft string         `json:"issue_draft,omitempty"`
	Source     string         `json:"source"` // rule | ai
}

// SuggestedSuppression is a YAML stub for accepted risk.
type SuggestedSuppression struct {
	ID     string `json:"id" yaml:"id"`
	Until  string `json:"until" yaml:"until"`
	Ticket string `json:"ticket" yaml:"ticket"`
	Reason string `json:"reason" yaml:"reason"`
}

// Report is the triage assistant output.
type Report struct {
	Target       string                 `json:"target"`
	GeneratedAt  time.Time              `json:"generated_at"`
	Groups       []Group                `json:"groups"`
	Suppressions []SuggestedSuppression `json:"suggested_suppressions"`
	SuppressYAML string                 `json:"suppressions_yaml"`
	AIEnriched   bool                   `json:"ai_enriched,omitempty"`
}

// Options controls triage generation.
type Options struct {
	AI bool
	remediate.Options
}

// Generate builds deterministic groups; optionally enriches with AI.
func Generate(ctx context.Context, result *scan.Result, opts Options) (*Report, error) {
	rep := &Report{
		Target:      result.Target,
		GeneratedAt: time.Now().UTC(),
	}
	byKey := map[string][]scan.Finding{}
	for _, f := range result.Findings {
		key := groupKey(f)
		byKey[key] = append(byKey[key], f)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fs := byKey[key]
		g := Group{
			Key:        key,
			Title:      groupTitle(fs),
			Findings:   fs,
			Source:     "rule",
			Narrative:  ruleNarrative(fs),
			Actions:    ruleActions(fs),
			IssueDraft: issueDraft(fs),
		}
		for _, f := range fs {
			g.FindingIDs = append(g.FindingIDs, f.ID())
			rep.Suppressions = append(rep.Suppressions, SuggestedSuppression{
				ID:     f.ID(),
				Until:  "YYYY-MM-DD",
				Ticket: "TICKET-ID",
				Reason: "Accepted risk — replace with justification",
			})
		}
		if opts.AI && opts.APIKey != "" {
			if enriched, err := enrichGroupAI(ctx, opts.Options, g); err == nil {
				g = enriched
				rep.AIEnriched = true
			}
		}
		rep.Groups = append(rep.Groups, g)
	}

	y, _ := yaml.Marshal(map[string]any{"suppressions": rep.Suppressions})
	rep.SuppressYAML = string(y)
	return rep, nil
}

func groupKey(f scan.Finding) string {
	if f.Kind == scan.KindVuln && f.Package.Name != "" {
		return string(f.Kind) + "|" + f.Package.Ecosystem + "|" + f.Package.Name
	}
	if f.VulnID != "" {
		return string(f.Kind) + "|" + f.VulnID
	}
	return string(f.Kind) + "|" + f.ID()
}

func groupTitle(fs []scan.Finding) string {
	if len(fs) == 0 {
		return "findings"
	}
	f := fs[0]
	if f.Kind == scan.KindVuln && f.Package.Name != "" {
		return fmt.Sprintf("%s %s (%d finding(s))", f.Package.Ecosystem, f.Package.Name, len(fs))
	}
	return fmt.Sprintf("%s: %s (%d)", f.Kind, f.ID(), len(fs))
}

func ruleNarrative(fs []scan.Finding) string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.ID())
	}
	return fmt.Sprintf("Grouped %d finding(s): %s. Detection is deterministic; review for exploitability and upgrade path.",
		len(fs), strings.Join(ids, ", "))
}

func ruleActions(fs []scan.Finding) []string {
	var actions []string
	seen := map[string]struct{}{}
	for _, f := range fs {
		s := remediateRuleActions(f)
		for _, a := range s {
			if _, ok := seen[a]; ok {
				continue
			}
			seen[a] = struct{}{}
			actions = append(actions, a)
		}
	}
	return actions
}

func remediateRuleActions(f scan.Finding) []string {
	rep, _ := remediate.Generate(context.Background(), &scan.Result{Findings: []scan.Finding{f}}, remediate.Options{})
	if len(rep.Suggestions) == 0 {
		return nil
	}
	return rep.Suggestions[0].Actions
}

func issueDraft(fs []scan.Finding) string {
	var b strings.Builder
	b.WriteString("## Foxhole finding group\n\n")
	b.WriteString(ruleNarrative(fs))
	b.WriteString("\n\n### Findings\n")
	for _, f := range fs {
		fmt.Fprintf(&b, "- **%s** (%s / %s): %s\n", f.ID(), f.Kind, f.Severity, f.Summary)
	}
	b.WriteString("\n### Suggested suppression (if accepting risk)\n\n```yaml\n")
	var stubs []SuggestedSuppression
	for _, f := range fs {
		stubs = append(stubs, SuggestedSuppression{
			ID: f.ID(), Until: "YYYY-MM-DD", Ticket: "TICKET-ID", Reason: "…",
		})
	}
	y, _ := yaml.Marshal(map[string]any{"suppressions": stubs})
	b.Write(y)
	b.WriteString("```\n")
	return b.String()
}

// WriteJSON encodes the triage report.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteMarkdown writes a human-readable triage report.
func WriteMarkdown(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "# Foxhole triage\n\nTarget: `%s`\n\nGenerated: %s\n\n", r.Target, r.GeneratedAt.Format(time.RFC3339))
	for _, g := range r.Groups {
		fmt.Fprintf(w, "## %s\n\n%s\n\n", g.Title, g.Narrative)
		if len(g.Actions) > 0 {
			fmt.Fprintln(w, "### Actions")
			for _, a := range g.Actions {
				fmt.Fprintf(w, "- %s\n", a)
			}
			fmt.Fprintln(w)
		}
		if g.IssueDraft != "" {
			fmt.Fprintln(w, "### Issue draft")
			fmt.Fprintln(w)
			fmt.Fprintln(w, g.IssueDraft)
		}
	}
	if r.SuppressYAML != "" {
		fmt.Fprintln(w, "## Suggested suppressions")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "```yaml")
		fmt.Fprint(w, r.SuppressYAML)
		fmt.Fprintln(w, "```")
	}
	return nil
}

// FindingDraft returns issue body for a single finding, using triage group if present.
func FindingDraft(rep *Report, f scan.Finding) string {
	if rep != nil {
		for _, g := range rep.Groups {
			for _, id := range g.FindingIDs {
				if id == f.ID() {
					if g.IssueDraft != "" {
						return g.IssueDraft
					}
					break
				}
			}
		}
	}
	return issueDraft([]scan.Finding{f})
}
