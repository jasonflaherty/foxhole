package notify_test

import (
	"context"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/notify"
	"github.com/jasonflaherty/foxhole/internal/scan"
)

func TestEmailNotify(t *testing.T) {
	var gotAddr, gotFrom string
	var gotTo []string
	var gotMsg []byte
	n := notify.EmailNotifier{
		Host: "smtp.example.com",
		Port: "587",
		From: "foxhole@example.com",
		To:   "sec@example.com,ops@example.com",
		SendMail: func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
			gotAddr, gotFrom, gotTo, gotMsg = addr, from, to, msg
			return nil
		},
	}
	err := n.Notify(context.Background(), &scan.Result{
		Target: "/app",
		Findings: []scan.Finding{{
			Kind: scan.KindVuln, VulnID: "CVE-1", Summary: "x", Severity: "high", Source: "nvd",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != "smtp.example.com:587" || gotFrom != "foxhole@example.com" {
		t.Fatalf("addr/from = %q %q", gotAddr, gotFrom)
	}
	if len(gotTo) != 2 {
		t.Fatalf("to = %#v", gotTo)
	}
	if !strings.Contains(string(gotMsg), "CVE-1") || !strings.Contains(string(gotMsg), "Subject:") {
		t.Fatalf("msg = %s", gotMsg)
	}
}

func TestGitHubNotify(t *testing.T) {
	var gotURL, gotAuth string
	client := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		gotAuth = req.Header.Get("Authorization")
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{"id":1}`))}, nil
	})
	n := notify.GitHubNotifier{Token: "tok", Repo: "acme/app", Client: client}
	err := n.Notify(context.Background(), &scan.Result{
		Target: "/app",
		Findings: []scan.Finding{{
			Kind: scan.KindSecret, RuleID: "aws-access-key", Summary: "key", Severity: "critical", Source: "secrets",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotURL != "https://api.github.com/repos/acme/app/issues" {
		t.Fatalf("url = %q", gotURL)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth = %q", gotAuth)
	}
}
