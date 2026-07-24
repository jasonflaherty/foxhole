package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Suggestion is a remediation recommendation for one finding.
type Suggestion struct {
	FindingID   string   `json:"finding_id"`
	Kind        string   `json:"kind"`
	Title       string   `json:"title"`
	Actions     []string `json:"actions"`
	FixedHint   string   `json:"fixed_hint,omitempty"`
	Source      string   `json:"source"` // rule | ai
	AIGenerated bool     `json:"ai_generated,omitempty"`
}

// Report holds remediation suggestions for a scan.
type Report struct {
	Target      string       `json:"target"`
	GeneratedAt time.Time    `json:"generated_at"`
	Suggestions []Suggestion `json:"suggestions"`
}

// Options controls remediation generation.
type Options struct {
	// AI enables optional LLM enrichment via OpenAI-compatible API.
	AI     bool
	APIKey string
	APIURL string // default https://api.openai.com/v1/chat/completions
	Model  string
	Client *http.Client
}

// FromEnv loads AI options from the environment.
func FromEnv() Options {
	return Options{
		APIKey: firstEnv("FOXHOLE_AI_API_KEY", "OPENAI_API_KEY"),
		APIURL: envOr("FOXHOLE_AI_API_URL", "https://api.openai.com/v1/chat/completions"),
		Model:  envOr("FOXHOLE_AI_MODEL", "gpt-4o-mini"),
		Client: http.DefaultClient,
	}
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Generate builds rule-based suggestions, optionally enriched by AI.
func Generate(ctx context.Context, result *scan.Result, opts Options) (*Report, error) {
	rep := &Report{
		Target:      result.Target,
		GeneratedAt: time.Now().UTC(),
	}
	for _, f := range result.Findings {
		s := ruleBased(f)
		if opts.AI && opts.APIKey != "" {
			if enriched, err := enrichAI(ctx, opts, f, s); err == nil {
				s = enriched
			}
		}
		rep.Suggestions = append(rep.Suggestions, s)
	}
	return rep, nil
}

func ruleBased(f scan.Finding) Suggestion {
	s := Suggestion{
		FindingID: f.ID(),
		Kind:      string(f.Kind),
		Source:    "rule",
	}
	switch f.Kind {
	case scan.KindVuln:
		s.Title = fmt.Sprintf("Remediate %s in %s@%s", f.ID(), f.Package.Name, f.Package.Version)
		s.Actions = []string{
			"Review the advisory and confirm exploitability in your environment.",
			"Upgrade the dependency to a fixed release when available.",
			"Re-run foxhole after upgrading to verify the finding is cleared.",
		}
		if f.Fixed != "" {
			s.FixedHint = f.Fixed
			s.Actions = append([]string{fmt.Sprintf("Upgrade %s to %s (or newer).", f.Package.Name, f.Fixed)}, s.Actions...)
		}
		if f.InKEV {
			s.Actions = append([]string{"Priority: this CVE is on the CISA KEV catalog — patch urgently."}, s.Actions...)
		}
	case scan.KindSecret:
		s.Title = fmt.Sprintf("Rotate exposed secret (%s)", f.ID())
		s.Actions = []string{
			"Treat the credential as compromised; revoke/rotate it immediately.",
			"Remove the secret from source history and config files.",
			"Move secrets to a vault or CI secret store; add pre-commit secret scanning.",
		}
	case scan.KindEOL:
		s.Title = fmt.Sprintf("Upgrade EOL %s %s", f.Product, f.Cycle)
		s.Actions = []string{
			fmt.Sprintf("Upgrade %s from cycle %s to a supported release.", f.Product, f.Cycle),
			"Update CI images and runtime pins to match.",
			"Re-scan to confirm the EOL finding is resolved.",
		}
	case scan.KindMisconfig:
		s.Title = fmt.Sprintf("Fix misconfiguration: %s", f.ID())
		s.Actions = []string{
			f.Summary,
			"Apply the recommended Dockerfile/K8s hardening change.",
			"Re-scan the path after fixing.",
		}
	case scan.KindLicense:
		s.Title = fmt.Sprintf("Review license risk: %s", f.ID())
		s.Actions = []string{
			"Confirm the license is acceptable for your distribution model.",
			"Replace the dependency or obtain legal approval if needed.",
		}
	default:
		s.Title = "Review finding " + f.ID()
		s.Actions = []string{f.Summary}
	}
	return s
}

type chatReq struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type chatResp struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func enrichAI(ctx context.Context, opts Options, f scan.Finding, base Suggestion) (Suggestion, error) {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	prompt := fmt.Sprintf(
		`You are a security engineer. Given this Foxhole finding, reply with 2-4 short concrete remediation steps as a JSON array of strings only.
Finding kind=%s id=%s severity=%s summary=%q package=%s@%s fixed=%q`,
		f.Kind, f.ID(), f.Severity, f.Summary, f.Package.Name, f.Package.Version, f.Fixed,
	)
	body, _ := json.Marshal(chatReq{
		Model: opts.Model,
		Messages: []chatMessage{
			{Role: "system", Content: "Return only a JSON array of strings."},
			{Role: "user", Content: prompt},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.APIURL, bytes.NewReader(body))
	if err != nil {
		return base, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return base, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return base, fmt.Errorf("ai api status %d: %s", resp.StatusCode, string(raw))
	}
	var cr chatResp
	if err := json.Unmarshal(raw, &cr); err != nil {
		return base, err
	}
	if len(cr.Choices) == 0 {
		return base, fmt.Errorf("ai empty response")
	}
	content := strings.TrimSpace(cr.Choices[0].Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	var actions []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &actions); err != nil || len(actions) == 0 {
		return base, fmt.Errorf("parse ai actions: %w", err)
	}
	base.Actions = actions
	base.Source = "ai"
	base.AIGenerated = true
	return base, nil
}

// WriteJSON writes the remediation report as JSON.
func WriteJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteMarkdown writes a human-readable remediation guide.
func WriteMarkdown(w io.Writer, rep *Report) error {
	fmt.Fprintf(w, "# Foxhole remediation — %s\n\n", rep.Target)
	fmt.Fprintf(w, "Generated: %s\n\n", rep.GeneratedAt.Format(time.RFC3339))
	if len(rep.Suggestions) == 0 {
		fmt.Fprintln(w, "No findings to remediate.")
		return nil
	}
	for i, s := range rep.Suggestions {
		fmt.Fprintf(w, "## %d. %s\n\n", i+1, s.Title)
		fmt.Fprintf(w, "- Finding: `%s` (%s)\n", s.FindingID, s.Kind)
		if s.FixedHint != "" {
			fmt.Fprintf(w, "- Fixed version hint: `%s`\n", s.FixedHint)
		}
		fmt.Fprintf(w, "- Source: %s\n\n", s.Source)
		for _, a := range s.Actions {
			fmt.Fprintf(w, "1. %s\n", a)
		}
		fmt.Fprintln(w)
	}
	return nil
}
