package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/dbbundle"
	"github.com/jasonflaherty/foxhole/internal/logger"
	"github.com/jasonflaherty/foxhole/internal/policy"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/seeds"
	"github.com/jasonflaherty/foxhole/internal/version"
	"github.com/jasonflaherty/foxhole/pkg/provider"
	"github.com/jasonflaherty/foxhole/pkg/provider/epss"
	"github.com/jasonflaherty/foxhole/pkg/provider/ghsa"
	"github.com/jasonflaherty/foxhole/pkg/provider/kev"
	"github.com/jasonflaherty/foxhole/pkg/provider/nvd"
	"github.com/jasonflaherty/foxhole/pkg/provider/osv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// NewRootCommand builds the foxhole CLI.
func NewRootCommand() *cobra.Command {
	v := config.NewViper()

	root := &cobra.Command{
		Use:   "foxhole [path]",
		Short: "Offline-first workspace CI gate for supply-chain findings",
		Long: `Foxhole scans a workspace for dependency vulns, secrets, EOL runtimes,
risky licenses, and Dockerfile issues — one findings list, deterministic
exit codes for CI (0 OK, 1 tool/stale DB, 2 policy).

Typical flow:
  foxhole db update .                 # refresh local vuln DB
  foxhole . --policy policy.yaml      # scan + gate
  foxhole . --evidence --offline      # audit pack from air-gapped DB

See docs/V1.md for the supported product contract.`,
		Version:       version.Version,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Flags())
			_ = v.BindPFlags(cmd.PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			if err := logger.Init(cfg.LogLevel, false); err != nil {
				return err
			}
			cmd.SetContext(withConfig(cmd.Context(), cfg, v))
			return nil
		},
		RunE: runScan,
	}

	registerGlobalFlags(root, v)
	groups := registerRootFlags(root, v)
	setGroupedHelp(root, groups)

	root.AddCommand(newDBCommand(v))
	root.AddCommand(newVersionCommand())
	root.AddCommand(newHistoryCommand(v))
	root.AddCommand(newDiffCommand(v))
	root.AddCommand(newServeCommand(v))
	root.AddCommand(newPolicyCommand())
	return root
}

func checkDBFreshness(cmd *cobra.Command, database *db.DB, maxAgeRaw string) error {
	maxAgeRaw = strings.TrimSpace(maxAgeRaw)
	if maxAgeRaw == "" || maxAgeRaw == "0" || maxAgeRaw == "off" || maxAgeRaw == "none" {
		return nil
	}
	maxAge, err := time.ParseDuration(maxAgeRaw)
	if err != nil {
		return fmt.Errorf("invalid --max-db-age %q: %w", maxAgeRaw, err)
	}
	if maxAge <= 0 {
		return nil
	}
	synced, ok, err := database.LastSyncAt(cmd.Context())
	if err != nil {
		return err
	}
	if !ok {
		return &ExitError{
			Code: 1,
			Err:  fmt.Errorf("vulnerability DB has no last_sync_at; run foxhole db update (max-db-age %s)", maxAge),
		}
	}
	age := time.Since(synced)
	if age > maxAge {
		return &ExitError{
			Code: 1,
			Err: fmt.Errorf("vulnerability DB is stale: last sync %s (%s ago), max-db-age %s; run foxhole db update",
				synced.Format(time.RFC3339), age.Round(time.Minute), maxAge),
		}
	}
	return nil
}

func loadScanPolicy(cfg *config.Config, cmd *cobra.Command) (policy.Policy, error) {
	var base policy.Policy
	if dir := cfg.PolicyDir; dir != "" {
		loaded, err := policy.LoadDir(expandPath(dir))
		if err != nil {
			return policy.Policy{}, err
		}
		base = loaded
	}
	path := cfg.PolicyPath
	if path != "" {
		loaded, err := policy.LoadFile(expandPath(path))
		if err != nil {
			return policy.Policy{}, err
		}
		if cfg.PolicyDir != "" {
			base = policy.MergePolicies(base, loaded)
		} else {
			base = loaded
		}
	}
	kinds, _ := cmd.Flags().GetStringSlice("fail-on-kind")
	return policy.Merge(base, cfg.FailOn, kinds), nil
}

func newDBCommand(v *viper.Viper) *cobra.Command {
	dbCmd := &cobra.Command{
		Use:   "db",
		Short: "Manage the local vulnerability database",
	}

	updateCmd := &cobra.Command{
		Use:   "update [path]",
		Short: "Update NVD, OSV, GHSA, KEV, and EPSS data in the local DB",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Flags())
			_ = v.BindPFlags(cmd.Root().PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			maxPkgs, _ := cmd.Flags().GetInt("max-packages")
			directOnly, _ := cmd.Flags().GetBool("direct-only")
			return runDBUpdate(cmd, cfg, target, maxPkgs, directOnly)
		},
	}
	updateCmd.Flags().Int("max-packages", 0, "limit packages queried from OSV (0 = unlimited)")
	updateCmd.Flags().Bool("direct-only", false, "use package.json / go.mod direct deps instead of full lockfiles")
	dbCmd.AddCommand(updateCmd)

	dbCmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Verify provider content hashes",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Root().PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			return runDBVerify(cmd, cfg)
		},
	})

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export vulnerability DB as a signed-ready tar.gz bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Root().PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			out, _ := cmd.Flags().GetString("output")
			database, err := db.Open(expandPath(cfg.DBPath))
			if err != nil {
				return err
			}
			defer func() { _ = database.Close() }()
			path, err := dbbundle.Export(cmd.Context(), database, out)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "exported %s\n", path)
			return nil
		},
	}
	exportCmd.Flags().StringP("output", "o", "", "output path (default foxhole-db-YYYYMMDD.tar.gz)")
	dbCmd.AddCommand(exportCmd)

	importCmd := &cobra.Command{
		Use:   "import PATH",
		Short: "Import a DB bundle into --db-path (verifies digest)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = v.BindPFlags(cmd.Root().PersistentFlags())
			cfg, err := config.FromViper(v)
			if err != nil {
				return err
			}
			meta, err := dbbundle.Import(args[0], expandPath(cfg.DBPath))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "imported bundle schema=%s last_sync=%s into %s\n",
				meta.SchemaVersion, meta.LastSyncAt, expandPath(cfg.DBPath))
			return nil
		},
	}
	dbCmd.AddCommand(importCmd)

	return dbCmd
}

func runDBUpdate(cmd *cobra.Command, cfg *config.Config, target string, maxPackages int, directOnly bool) error {
	database, err := db.Open(expandPath(cfg.DBPath))
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	if err := ensurePhase2Data(cmd.Context(), database); err != nil {
		return err
	}

	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}

	var pkgs []provider.PackageQuery
	if !cfg.Offline {
		fs := scan.NewFilesystemScanner()
		discovered, err := fs.ScanWithOptions(abs, scan.ScanOptions{
			DirectOnly:  directOnly,
			MaxPackages: maxPackages,
		})
		if err != nil {
			logger.L().Warn("package discovery failed", zap.Error(err))
		} else {
			logger.L().Info("discovered packages for update",
				zap.String("target", abs),
				zap.Int("count", len(discovered)),
				zap.Bool("direct_only", directOnly),
			)
			for _, p := range discovered {
				pkgs = append(pkgs, provider.PackageQuery{
					Ecosystem: p.Ecosystem,
					Name:      p.Name,
					Version:   p.Version,
				})
			}
		}
	}

	reg := provider.NewRegistry()
	osvOpts := []osv.Option{osv.WithOffline(cfg.Offline), osv.WithPackages(pkgs)}
	nvdOpts := []nvd.Option{nvd.WithOffline(cfg.Offline), nvd.WithAPIKey(cfg.NVDAPIKey)}
	if cfg.Offline {
		osvOpts = append(osvOpts, osv.WithSeedAdvisories(seeds.OSV))
		nvdOpts = append(nvdOpts, nvd.WithSeedCVEs(seeds.NVD))
	}
	reg.Register(osv.New(database, osvOpts...))
	reg.Register(nvd.New(database, nvdOpts...))
	reg.Register(ghsa.New(database))
	reg.Register(kev.New(database, kev.WithOffline(cfg.Offline)))
	reg.Register(epss.New(database, epss.WithOffline(true)))

	results, err := reg.UpdateAll(cmd.Context())
	if err != nil {
		return err
	}
	for id, res := range results {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %d records (sha256=%s)\n", id, res.Records, shortHash(res.ContentHash))
	}
	if err := database.UpdateDBHash(cmd.Context()); err != nil {
		logger.L().Warn("db hash update failed", zap.Error(err))
	}
	cves, adv, _ := database.CountVulns(cmd.Context())
	secrets, _ := database.CountSecretRules(cmd.Context())
	eols, _ := database.CountEOL(cmd.Context())
	kevN, _ := database.CountKEV(cmd.Context())
	epssN, _ := database.CountEPSS(cmd.Context())
	licN, _ := database.CountLicenses(cmd.Context())
	fmt.Fprintf(cmd.OutOrStdout(), "database ready: %d CVEs, %d advisories, %d secret rules, %d eol, %d kev, %d epss, %d licenses at %s\n",
		cves, adv, secrets, eols, kevN, epssN, licN, expandPath(cfg.DBPath))
	return nil
}

func runDBVerify(cmd *cobra.Command, cfg *config.Config) error {
	database, err := db.Open(expandPath(cfg.DBPath))
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	osvProv := osv.New(database, osv.WithOffline(true))
	nvdProv := nvd.New(database, nvd.WithOffline(true), nvd.WithAPIKey(cfg.NVDAPIKey))
	for _, p := range []provider.Provider{osvProv, nvdProv} {
		if err := p.Verify(cmd.Context()); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: ok\n", p.Metadata().ID)
	}
	ok, err := database.IntegrityOK(cmd.Context())
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("database sha256 mismatch")
	}
	fmt.Fprintln(cmd.OutOrStdout(), "database integrity: ok")
	if synced, ok, err := database.LastSyncAt(cmd.Context()); err != nil {
		return err
	} else if ok {
		fmt.Fprintf(cmd.OutOrStdout(), "last sync: %s (%s ago)\n",
			synced.Format(time.RFC3339), time.Since(synced).Round(time.Minute))
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "last sync: unknown (run foxhole db update)")
	}
	return nil
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Version)
		},
	}
}

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy pack utilities",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate [path]",
		Short: "Load and fingerprint a policy file or directory",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			path = expandPath(path)
			st, err := os.Stat(path)
			if err != nil {
				return err
			}
			var p policy.Policy
			if st.IsDir() {
				p, err = policy.LoadDir(path)
			} else {
				p, err = policy.LoadFile(path)
			}
			if err != nil {
				return err
			}
			fp, err := policy.Fingerprint(p)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "id=%s version=%s fail_on=%s kinds=%v fingerprint=%s\n",
				p.ID, p.Version, p.FailOn, p.Kinds, fp)
			_, expired := policy.ActiveSuppressions(p, time.Now().UTC())
			if len(expired) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "expired suppressions:")
				for _, s := range expired {
					fmt.Fprintf(cmd.OutOrStdout(), "  - %s until=%s ticket=%s\n", s.ID, s.Until, s.Ticket)
				}
			}
			return nil
		},
	})
	return cmd
}

func expandPath(p string) string {
	if p == "" {
		return config.DefaultDBPath()
	}
	if stringsHasHome(p) {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, stringsTrimHome(p))
		}
	}
	return p
}

func stringsHasHome(p string) bool {
	return len(p) >= 2 && p[0] == '~' && (p[1] == '/' || p[1] == filepath.Separator)
}

func stringsTrimHome(p string) string {
	if len(p) < 2 {
		return p
	}
	return p[2:]
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
