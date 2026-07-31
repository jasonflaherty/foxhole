package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/db"
)

func TestEnsurePhase2SeedsUpsertsSecretRules(t *testing.T) {
	t.Parallel()
	database, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()

	first := []db.SecretRule{{
		ID: "aws-access-key", Name: "AWS old", Pattern: `AKIA[0-9A-Z]{16}`,
		Severity: "high", Enabled: true,
	}}
	if err := database.EnsurePhase2Seeds(ctx, first, nil); err != nil {
		t.Fatal(err)
	}
	n, err := database.CountSecretRules(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count = %d err=%v", n, err)
	}

	second := []db.SecretRule{
		{
			ID: "aws-access-key", Name: "AWS Access Key ID", Pattern: `\bAKIA[0-9A-Z]{16}\b`,
			Severity: "critical", Enabled: true,
		},
		{
			ID: "jwt", Name: "JSON Web Token", Pattern: `\beyJ[A-Za-z0-9_-]+\.`,
			Severity: "high", Enabled: true,
		},
	}
	if err := database.EnsurePhase2Seeds(ctx, second, nil); err != nil {
		t.Fatal(err)
	}
	n, err = database.CountSecretRules(ctx)
	if err != nil || n != 2 {
		t.Fatalf("after upsert count = %d err=%v", n, err)
	}
	rules, err := database.ListSecretRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]db.SecretRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	if byID["aws-access-key"].Severity != "critical" || byID["aws-access-key"].Name != "AWS Access Key ID" {
		t.Fatalf("aws rule not updated: %+v", byID["aws-access-key"])
	}
	if _, ok := byID["jwt"]; !ok {
		t.Fatal("missing jwt rule after upsert")
	}
}
