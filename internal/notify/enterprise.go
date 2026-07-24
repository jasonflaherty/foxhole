package notify

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

	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/version"
)

// SlackNotifier posts to an Incoming Webhook.
type SlackNotifier struct {
	Webhook string
	Client  HTTPDoer
}

func (s SlackNotifier) Name() string { return "slack" }

func (s SlackNotifier) Notify(ctx context.Context, result *scan.Result) error {
	if s.Webhook == "" {
		return fmt.Errorf("slack: FOXHOLE_SLACK_WEBHOOK not set")
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	payload := map[string]any{
		"text": SummaryLine(result) + "\n" + topFindings(result, 10),
	}
	return postJSON(ctx, client, s.Webhook, payload)
}

// DiscordNotifier posts to a Discord webhook.
type DiscordNotifier struct {
	Webhook string
	Client  HTTPDoer
}

func (d DiscordNotifier) Name() string { return "discord" }

func (d DiscordNotifier) Notify(ctx context.Context, result *scan.Result) error {
	if d.Webhook == "" {
		return fmt.Errorf("discord: FOXHOLE_DISCORD_WEBHOOK not set")
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	payload := map[string]any{
		"content": SummaryLine(result),
		"embeds": []map[string]any{{
			"title":       "Foxhole findings",
			"description": topFindings(result, 10),
			"color":       12745798,
		}},
	}
	return postJSON(ctx, client, d.Webhook, payload)
}

// WebhookNotifier posts a generic JSON payload to any URL.
type WebhookNotifier struct {
	URL    string
	Client HTTPDoer
}

func (w WebhookNotifier) Name() string { return "webhook" }

func (w WebhookNotifier) Notify(ctx context.Context, result *scan.Result) error {
	if w.URL == "" {
		return fmt.Errorf("webhook: FOXHOLE_WEBHOOK_URL not set")
	}
	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	env := report.WrapResult(result)
	payload := map[string]any{
		"schema_version": env.SchemaVersion,
		"tool":           env.Tool,
		"tool_version":   version.Version,
		"summary":        SummaryLine(result),
		"result":         env.Result,
	}
	return postJSON(ctx, client, w.URL, payload)
}

// GitHubChecksNotifier creates a Check Run on the current commit (enterprise CI).
type GitHubChecksNotifier struct {
	Token  string
	Repo   string // owner/repo
	SHA    string
	Client HTTPDoer
}

func (g GitHubChecksNotifier) Name() string { return "github-checks" }

func (g GitHubChecksNotifier) Notify(ctx context.Context, result *scan.Result) error {
	if g.Token == "" || g.Repo == "" || g.SHA == "" {
		return fmt.Errorf("github-checks: token, repo, and sha required (FOXHOLE_GITHUB_TOKEN, FOXHOLE_GITHUB_REPO, FOXHOLE_GIT_SHA/GITHUB_SHA)")
	}
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}
	conclusion := "success"
	if len(result.Findings) > 0 {
		conclusion = "neutral"
	}
	payload := map[string]any{
		"name":         "Foxhole",
		"head_sha":     g.SHA,
		"status":       "completed",
		"conclusion":   conclusion,
		"completed_at": time.Now().UTC().Format(time.RFC3339),
		"output": map[string]any{
			"title":   SummaryLine(result),
			"summary": topFindings(result, 20),
		},
	}
	url := "https://api.github.com/repos/" + g.Repo + "/check-runs"
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github-checks: status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func postJSON(ctx context.Context, client HTTPDoer, url string, payload any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// Flags selects which notifiers to enable.
type Flags struct {
	GitHub       bool
	Teams        bool
	Email        bool
	Slack        bool
	Discord      bool
	Webhook      bool
	GitHubChecks bool
}

// SelectAll builds notifiers from flags + config/env.
func SelectAll(cfg Config, f Flags) []Notifier {
	var out []Notifier
	out = append(out, Select(cfg, f.GitHub, f.Teams, f.Email)...)
	if f.Slack {
		out = append(out, SlackNotifier{Webhook: firstNonEmpty(cfg.SlackWebhook, os.Getenv("FOXHOLE_SLACK_WEBHOOK")), Client: cfg.Client})
	}
	if f.Discord {
		out = append(out, DiscordNotifier{Webhook: firstNonEmpty(cfg.DiscordWebhook, os.Getenv("FOXHOLE_DISCORD_WEBHOOK")), Client: cfg.Client})
	}
	if f.Webhook {
		out = append(out, WebhookNotifier{URL: firstNonEmpty(cfg.WebhookURL, os.Getenv("FOXHOLE_WEBHOOK_URL")), Client: cfg.Client})
	}
	if f.GitHubChecks {
		out = append(out, GitHubChecksNotifier{
			Token: cfg.GitHubToken, Repo: cfg.GitHubRepo,
			SHA:    firstNonEmpty(cfg.GitSHA, firstEnv("FOXHOLE_GIT_SHA", "GITHUB_SHA")),
			Client: cfg.Client,
		})
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
