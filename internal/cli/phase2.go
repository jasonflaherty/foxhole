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
	if err := database.EnsurePhase2Seeds(ctx, secretRules, eolRecords); err != nil {
		return err
	}
	return ensureEnrichmentData(ctx, database)
}

func ensureEnrichmentData(ctx context.Context, database *db.DB) error {
	n, err := database.CountKEV(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		rows, err := seeds.KEVRecords()
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := database.UpsertKEV(ctx, r.CVEID, r.VendorProject, r.Product, r.DateAdded, r.DueDate, r.KnownRansomware); err != nil {
				return err
			}
		}
	}
	n, err = database.CountEPSS(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		rows, err := seeds.EPSSRecords()
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := database.UpsertEPSS(ctx, r.CVEID, r.Score, r.Percentile); err != nil {
				return err
			}
		}
	}
	n, err = database.CountLicenses(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		rows, err := seeds.LicenseRecords()
		if err != nil {
			return err
		}
		for _, r := range rows {
			if err := database.UpsertLicense(ctx, r.ID, r.Name, r.SPDX, r.Risk, r.OSIApproved); err != nil {
				return err
			}
		}
	}
	return nil
}
