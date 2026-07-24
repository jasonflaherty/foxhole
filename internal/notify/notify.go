package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// Notifier sends scan results to an external channel.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, result *scan.Result) error
}

// HTTPDoer abstracts HTTP for tests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds notification credentials from the environment.
type Config struct {
	TeamsWebhook string
	GitHubToken  string
	GitHubRepo   string // owner/repo
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPass     string
	EmailFrom    string
	EmailTo      string
	Client       HTTPDoer
}

// FromEnv loads notification settings.
func FromEnv() Config {
	return Config{
		TeamsWebhook: os.Getenv("FOXHOLE_TEAMS_WEBHOOK"),
		GitHubToken:  firstEnv("FOXHOLE_GITHUB_TOKEN", "GITHUB_TOKEN"),
		GitHubRepo:   firstEnv("FOXHOLE_GITHUB_REPO", "GITHUB_REPOSITORY"),
		SMTPHost:     os.Getenv("FOXHOLE_SMTP_HOST"),
		SMTPPort:     envOr("FOXHOLE_SMTP_PORT", "587"),
		SMTPUser:     os.Getenv("FOXHOLE_SMTP_USER"),
		SMTPPass:     os.Getenv("FOXHOLE_SMTP_PASS"),
		EmailFrom:    os.Getenv("FOXHOLE_EMAIL_FROM"),
		EmailTo:      os.Getenv("FOXHOLE_EMAIL_TO"),
		Client:       http.DefaultClient,
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// SummaryLine builds a short notification body.
func SummaryLine(result *scan.Result) string {
	return fmt.Sprintf("Foxhole scan of %s: %d findings across %d packages",
		result.Target, len(result.Findings), result.Packages)
}

// TeamsNotifier posts an Adaptive Card-like simple message to a Teams webhook.
type TeamsNotifier struct {
	Webhook string
	Client  HTTPDoer
}

func (t TeamsNotifier) Name() string { return "teams" }

func (t TeamsNotifier) Notify(ctx context.Context, result *scan.Result) error {
	if t.Webhook == "" {
		return fmt.Errorf("teams: FOXHOLE_TEAMS_WEBHOOK not set")
	}
	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	payload := map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    "Foxhole scan",
		"themeColor": themeColor(result),
		"title":      "Foxhole scan results",
		"text":       SummaryLine(result) + "\n\n" + topFindings(result, 5),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Webhook, bytes.NewReader(body))
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
		return fmt.Errorf("teams: status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// GitHubNotifier opens an issue on the configured repository.
type GitHubNotifier struct {
	Token  string
	Repo   string
	Client HTTPDoer
}

func (g GitHubNotifier) Name() string { return "github" }

func (g GitHubNotifier) Notify(ctx context.Context, result *scan.Result) error {
	if g.Token == "" || g.Repo == "" {
		return fmt.Errorf("github: FOXHOLE_GITHUB_TOKEN and FOXHOLE_GITHUB_REPO (owner/repo) required")
	}
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}
	payload := map[string]any{
		"title": fmt.Sprintf("Foxhole: %d findings in %s", len(result.Findings), result.Target),
		"body":  SummaryLine(result) + "\n\n" + topFindings(result, 20),
	}
	body, _ := json.Marshal(payload)
	url := "https://api.github.com/repos/" + g.Repo + "/issues"
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
		return fmt.Errorf("github: status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// EmailNotifier sends a plain-text email via SMTP.
type EmailNotifier struct {
	Host string
	Port string
	User string
	Pass string
	From string
	To   string
	// SendMail allows tests to stub SMTP.
	SendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

func (e EmailNotifier) Name() string { return "email" }

func (e EmailNotifier) Notify(ctx context.Context, result *scan.Result) error {
	_ = ctx
	if e.Host == "" || e.From == "" || e.To == "" {
		return fmt.Errorf("email: FOXHOLE_SMTP_HOST, FOXHOLE_EMAIL_FROM, FOXHOLE_EMAIL_TO required")
	}
	to := strings.Split(e.To, ",")
	subject := fmt.Sprintf("Foxhole: %d findings in %s", len(result.Findings), result.Target)
	msg := []byte("From: " + e.From + "\r\n" +
		"To: " + e.To + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" +
		SummaryLine(result) + "\r\n\r\n" + topFindings(result, 20) + "\r\n")
	addr := e.Host + ":" + e.Port
	var auth smtp.Auth
	if e.User != "" {
		auth = smtp.PlainAuth("", e.User, e.Pass, e.Host)
	}
	send := e.SendMail
	if send == nil {
		send = smtp.SendMail
	}
	return send(addr, auth, e.From, to, msg)
}

func themeColor(result *scan.Result) string {
	if len(result.Findings) == 0 {
		return "2EA043"
	}
	return "CF222E"
}

func topFindings(result *scan.Result, n int) string {
	var b strings.Builder
	limit := n
	if len(result.Findings) < limit {
		limit = len(result.Findings)
	}
	for i := 0; i < limit; i++ {
		f := result.Findings[i]
		fmt.Fprintf(&b, "- [%s] %s (%s): %s\n", strings.ToUpper(f.Severity), f.ID(), f.Kind, f.Summary)
	}
	if len(result.Findings) > n {
		fmt.Fprintf(&b, "- …and %d more\n", len(result.Findings)-n)
	}
	return b.String()
}

// Select builds notifiers from flags + config.
func Select(cfg Config, github, teams, email bool) []Notifier {
	var out []Notifier
	if github {
		out = append(out, GitHubNotifier{Token: cfg.GitHubToken, Repo: cfg.GitHubRepo, Client: cfg.Client})
	}
	if teams {
		out = append(out, TeamsNotifier{Webhook: cfg.TeamsWebhook, Client: cfg.Client})
	}
	if email {
		out = append(out, EmailNotifier{
			Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser, Pass: cfg.SMTPPass,
			From: cfg.EmailFrom, To: cfg.EmailTo,
		})
	}
	return out
}
