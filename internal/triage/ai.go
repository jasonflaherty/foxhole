package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/remediate"
)

func enrichGroupAI(ctx context.Context, opts remediate.Options, g Group) (Group, error) {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	prompt := fmt.Sprintf(
		"You are a security triage assistant. Detection already ran; do not invent new findings. "+
			"Write a short narrative (2-4 sentences) and a GitHub issue body draft for this group.\n"+
			"Title: %s\nFinding IDs: %s\nCurrent narrative: %s\n"+
			"Reply as JSON: {\"narrative\":\"...\",\"issue_draft\":\"...\",\"actions\":[\"...\"]}",
		g.Title, strings.Join(g.FindingIDs, ", "), g.Narrative,
	)
	payload := map[string]any{
		"model": opts.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.2,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.APIURL, bytes.NewReader(body))
	if err != nil {
		return g, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return g, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return g, fmt.Errorf("ai status %d: %s", resp.StatusCode, string(b))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return g, err
	}
	if len(parsed.Choices) == 0 {
		return g, fmt.Errorf("ai: empty response")
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	var out struct {
		Narrative  string   `json:"narrative"`
		IssueDraft string   `json:"issue_draft"`
		Actions    []string `json:"actions"`
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return g, err
	}
	if out.Narrative != "" {
		g.Narrative = out.Narrative
	}
	if out.IssueDraft != "" {
		g.IssueDraft = out.IssueDraft
	}
	if len(out.Actions) > 0 {
		g.Actions = out.Actions
	}
	g.Source = "ai"
	return g, nil
}
