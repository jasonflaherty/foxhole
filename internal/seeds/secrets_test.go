package seeds_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/seeds"
)

func TestSecretRulesCompileAndMatch(t *testing.T) {
	t.Parallel()
	rules, err := seeds.SecretRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 15 {
		t.Fatalf("expected curated pack (>=15 rules), got %d", len(rules))
	}

	// Build samples at runtime so source text does not trip push protection.
	samples := map[string]string{
		"aws-access-key":            "key = \"" + "AKIA" + "IOSFODNN7EXAMPLE\"",
		"aws-secret-access-key":     "aws_secret_access_key = \"" + strings.Repeat("A", 40) + "\"",
		"gcp-api-key":               "AIza" + "SyA-" + "abcdefghijklmnopqrstuvwxyz12345",
		"gcp-service-account":       `{"type": "service_account", "project_id": "x"}`,
		"azure-storage-account-key": "AccountKey=" + strings.Repeat("A", 60) + "==",
		"azure-ad-client-secret":    `AZURE_CLIENT_SECRET="super-secret-value-16"`,
		"github-pat":                "ghp_" + strings.Repeat("a", 36),
		"github-oauth":              "gho_" + strings.Repeat("a", 36),
		"github-app-token":          "ghs_" + strings.Repeat("a", 36),
		"github-refresh":            "ghr_" + strings.Repeat("a", 40),
		"github-fine-grained-pat":   "github_pat_" + strings.Repeat("a", 22) + "_" + strings.Repeat("b", 59),
		"private-key":               "-----BEGIN RSA PRIVATE KEY-----",
		"pgp-private-key":           "-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"jwt":                       "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0." + "testsig",
		"slack-token":               "xoxb-" + "foxholetesttoken",
		"slack-webhook":             "https://hooks.slack.com/services/" + "T_TEST/B_TEST/" + "foxhole_test_placeholder",
		"stripe-secret-key":         "sk_live_" + strings.Repeat("a", 24),
		"sendgrid-api-key":          "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 26),
		"twilio-api-key":            "SK" + strings.Repeat("0", 32),
		"generic-api-key":           `api_key = "abcdefghijklmnop1234"`,
	}

	byID := make(map[string]string, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			t.Fatalf("rule %s: compile: %v\npattern=%q", r.ID, err, r.Pattern)
		}
		byID[r.ID] = r.Pattern
		sample, ok := samples[r.ID]
		if !ok {
			t.Fatalf("missing sample for rule %s", r.ID)
		}
		if !re.MatchString(sample) {
			t.Fatalf("rule %s did not match sample %q\npattern=%q", r.ID, sample, r.Pattern)
		}
	}

	for id := range samples {
		if _, ok := byID[id]; !ok {
			t.Fatalf("sample for unknown/disabled rule %s", id)
		}
	}
}
