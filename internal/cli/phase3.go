package cli

import (
	"fmt"
	"path/filepath"

	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/diff"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newHistoryCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history [path]",
		Short: "List recent scan history",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Flags())
			_ = v.BindPFlags(cmd.Root().PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			limit, _ := cmd.Flags().GetInt("limit")
			target := ""
			if len(args) == 1 {
				abs, err := filepath.Abs(args[0])
				if err != nil {
					return err
				}
				target = abs
			}
			database, err := db.Open(expandPath(cfg.DBPath))
			if err != nil {
				return err
			}
			defer func() { _ = database.Close() }()

			rows, err := database.ListScanHistory(cmd.Context(), target, limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No scan history.")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%-6s %-8s %-8s %-20s %s\n", "ID", "FINDINGS", "STATUS", "STARTED", "TARGET")
			for _, r := range rows {
				started := r.StartedAt.Format("2006-01-02 15:04")
				if r.StartedAt.IsZero() {
					started = "-"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-6d %-8d %-8s %-20s %s\n",
					r.ID, r.FindingCount, r.Status, started, r.Target)
			}
			return nil
		},
	}
	cmd.Flags().Int("limit", 20, "maximum rows to list")
	return cmd
}

func newDiffCommand(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare scan results",
	}
	last := &cobra.Command{
		Use:   "last [path]",
		Short: "Diff the two most recent scans for a target",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Root().PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			abs, err := filepath.Abs(target)
			if err != nil {
				return err
			}
			database, err := db.Open(expandPath(cfg.DBPath))
			if err != nil {
				return err
			}
			defer func() { _ = database.Close() }()

			latest, previous, err := database.LastTwoScans(cmd.Context(), abs)
			if err != nil {
				return err
			}
			if latest == nil {
				return fmt.Errorf("no scan history for %s — run a scan first", abs)
			}
			if previous == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Only one scan for %s (id=%d, findings=%d). Run another scan to diff.\n",
					abs, latest.ID, latest.FindingCount)
				return nil
			}

			prevSet, err := diff.SetFromJSON(previous.FindingsJSON)
			if err != nil {
				return fmt.Errorf("previous findings: %w", err)
			}
			latestSet, err := diff.SetFromJSON(latest.FindingsJSON)
			if err != nil {
				return fmt.Errorf("latest findings: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Comparing scan %d → %d for %s\n", previous.ID, latest.ID, abs)
			diff.Write(cmd.OutOrStdout(), diff.Compare(prevSet, latestSet))
			return nil
		},
	}
	cmd.AddCommand(last)
	return cmd
}
