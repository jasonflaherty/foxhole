package cli

import (
	"context"
	"fmt"

	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/seeds"
)

func ensurePhase2Data(ctx context.Context, database *db.DB) error {
	secretRules, err := seeds.SecretRules()
	if err != nil {
		return fmt.Errorf("secret seeds: %w", err)
	}
	eolRecords, err := seeds.EOLRecords()
	if err != nil {
		return fmt.Errorf("eol seeds: %w", err)
	}
	return database.EnsurePhase2Seeds(ctx, secretRules, eolRecords)
}
