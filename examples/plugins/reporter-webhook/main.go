// Package webhookreporter implements a Reporter plugin for HTTP webhooks.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jasonflaherty/foxhole/pkg/sdk/reporter"
)

// WebhookReporter sends scan results to HTTP webhooks.
type WebhookReporter struct {
	cfg    reporter.ReporterConfig
	client *http.Client
}

// NewWebhookReporter creates a new webhook reporter instance.
func NewWebhookReporter() *WebhookReporter {
	return &WebhookReporter{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Metadata returns plugin information.
func (r *WebhookReporter) Metadata() reporter.ReporterMetadata {
	return reporter.ReporterMetadata{
		ID:          "webhook-reporter",
		Name:        "Webhook Reporter",
		Version:     "0.1.0",
		Description: "Sends scan findings to HTTP webhooks (Slack, Discord, custom)",
		Format:      "json",
		MimeType:    "application/json",
		Author:      "Foxhole Community",
		Repository:  "https://github.com/foxhole-plugins/reporter-webhook",
	}
}

// Validate checks if the configuration is valid.
func (r *WebhookReporter) Validate(cfg reporter.ReporterConfig) error {
	if cfg.Endpoint == "" {
		return fmt.Errorf("endpoint required")
	}
	return nil
}

// Configure applies settings to the reporter.
func (r *WebhookReporter) Configure(cfg reporter.ReporterConfig) error {
	if err := r.Validate(cfg); err != nil {
		return err
	}
	r.cfg = cfg
	return nil
}

// WebhookPayload is the structure sent to the webhook.
type WebhookPayload struct {
	Target     string                 `json:"target"`
	Timestamp  string                 `json:"timestamp"`
	Packages   int                    `json:"packages"`
	Findings   []reporter.Finding     `json:"findings"`
	Summary    map[string]interface{} `json:"summary"`
}

// summarizeFindings counts findings by severity.
func summarizeFindings(findings []reporter.Finding) map[string]interface{} {
	summary := map[string]interface{}{
		"total":    len(findings),
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			summary["critical"] = summary["critical"].(int) + 1
		case "HIGH":
			summary["high"] = summary["high"].(int) + 1
		case "MEDIUM":
			summary["medium"] = summary["medium"].(int) + 1
		case "LOW":
			summary["low"] = summary["low"].(int) + 1
		}
	}
	return summary
}

// Report sends findings to the configured webhook.
func (r *WebhookReporter) Report(result reporter.Result, w io.Writer) error {
	if r.cfg.Endpoint == "" {
		return fmt.Errorf("not configured")
	}

	payload := WebhookPayload{
		Target:    result.Target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Packages:  result.Packages,
		Findings:  result.Findings,
		Summary:   summarizeFindings(result.Findings),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", r.cfg.Endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if token, ok := r.cfg.Auth["token"]; ok {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	_, err = w.Write(data)
	return err
}

// Close performs cleanup.
func (r *WebhookReporter) Close() error {
	return nil
}

func main() {
	reporter := NewWebhookReporter()
	fmt.Println("Webhook Reporter Plugin")
	fmt.Printf("Name: %s\n", reporter.Metadata().Name)
}
