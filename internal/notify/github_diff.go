package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/diff"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/triage"
)

// GitHubDiffNotifier opens/closes issues for findings added/removed vs last green.
type GitHubDiffNotifier struct {
	Token    string
	Repo     string
	Client   HTTPDoer
	DB       *db.DB
	Previous map[string]scan.Finding // baseline (last green); nil = all findings are new
	Triage   *triage.Report
	Target   string
}

func (g GitHubDiffNotifier) Name() string { return "github-diff" }

func (g GitHubDiffNotifier) Notify(ctx context.Context, result *scan.Result) error {
	if g.Token == "" || g.Repo == "" {
		return fmt.Errorf("github-diff: FOXHOLE_GITHUB_TOKEN and FOXHOLE_GITHUB_REPO required")
	}
	if g.DB == nil {
		return fmt.Errorf("github-diff: database required for issue map")
	}
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}

	latest := map[string]scan.Finding{}
	for _, f := range result.Findings {
		latest[diff.Fingerprint(f)] = f
	}
	prev := g.Previous
	if prev == nil {
		prev = map[string]scan.Finding{}
	}
	cmp := diff.Compare(prev, latest)

	for _, f := range cmp.Added {
		fp := diff.Fingerprint(f)
		existing, err := g.DB.GetGitHubIssue(ctx, fp, g.Repo)
		if err != nil {
			return err
		}
		if existing != nil {
			continue // already tracked; do not reopen duplicates
		}
		body := triage.FindingDraft(g.Triage, f)
		title := fmt.Sprintf("Foxhole: [%s] %s", strings.ToUpper(string(f.Kind)), f.ID())
		num, err := createIssue(ctx, client, g.Token, g.Repo, title, body)
		if err != nil {
			return err
		}
		if err := g.DB.UpsertGitHubIssue(ctx, db.GitHubIssueRef{
			Fingerprint: fp,
			Repo:        g.Repo,
			IssueNumber: num,
			Target:      result.Target,
			FindingID:   f.ID(),
		}); err != nil {
			return err
		}
	}

	for _, f := range cmp.Removed {
		fp := diff.Fingerprint(f)
		existing, err := g.DB.GetGitHubIssue(ctx, fp, g.Repo)
		if err != nil {
			return err
		}
		if existing == nil {
			continue
		}
		comment := fmt.Sprintf("Closed by Foxhole: finding no longer present after scan of `%s`.", result.Target)
		if err := closeIssue(ctx, client, g.Token, g.Repo, existing.IssueNumber, comment); err != nil {
			return err
		}
	}
	return nil
}

func createIssue(ctx context.Context, client HTTPDoer, token, repo, title, body string) (int, error) {
	payload := map[string]any{"title": title, "body": body}
	raw, _ := json.Marshal(payload)
	url := "https://api.github.com/repos/" + repo + "/issues"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("github create issue: status %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Number int `json:"number"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return 0, err
	}
	return out.Number, nil
}

func closeIssue(ctx context.Context, client HTTPDoer, token, repo string, number int, comment string) error {
	if comment != "" {
		cURL := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", repo, number)
		raw, _ := json.Marshal(map[string]string{"body": comment})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cURL, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("github comment: status %d: %s", resp.StatusCode, string(b))
		}
	}
	pURL := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d", repo, number)
	raw, _ := json.Marshal(map[string]string{"state": "closed"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, pURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github close: status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
