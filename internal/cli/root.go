package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/logger"
	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/seeds"
	"github.com/jasonflaherty/foxhole/internal/version"
	"github.com/jasonflaherty/foxhole/pkg/provider"
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
		Use:           "foxhole [path]",
		Short:         "Offline-first software supply chain security scanner",
		Long:          "Foxhole scans projects for vulnerabilities using local NVD/OSV data.",
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

	root.PersistentFlags().String("db-path", config.DefaultDBPath(), "path to SQLite database")
	root.PersistentFlags().Bool("offline", false, "disable network access")
	root.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	root.PersistentFlags().String("nvd-api-key", "", "optional NVD API key")
	root.Flags().String("report", "console", "report formats: console,json,markdown,html,sarif (comma-separated)")
	root.Flags().Bool("secrets", true, "enable secret scanning")
	root.Flags().Bool("eol", true, "enable end-of-life checks")
	root.Flags().Bool("archive", false, "archive results (phase 3)")
	root.Flags().Bool("github", false, "notify GitHub (phase 3)")
	root.Flags().Bool("teams", false, "notify Teams (phase 3)")
	root.Flags().Bool("email", false, "notify email (phase 3)")

	_ = v.BindPFlag("db_path", root.PersistentFlags().Lookup("db-path"))
	_ = v.BindPFlag("offline", root.PersistentFlags().Lookup("offline"))
	_ = v.BindPFlag("log_level", root.PersistentFlags().Lookup("log-level"))
	_ = v.BindPFlag("nvd_api_key", root.PersistentFlags().Lookup("nvd-api-key"))
	_ = v.BindPFlag("report", root.Flags().Lookup("report"))
	_ = v.BindPFlag("secrets", root.Flags().Lookup("secrets"))
	_ = v.BindPFlag("eol", root.Flags().Lookup("eol"))

	root.AddCommand(newDBCommand(v))
	root.AddCommand(newVersionCommand())
	return root
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg := configFrom(cmd)
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

	if err := ensurePhase2Data(cmd.Context(), database); err != nil {
		return err
	}

	osvProv := osv.New(database, osv.WithOffline(cfg.Offline))
	nvdProv := nvd.New(database, nvd.WithOffline(cfg.Offline), nvd.WithAPIKey(cfg.NVDAPIKey))
	engine := scan.NewEngine(database, osvProv, nvdProv).WithOptions(scan.EngineOptions{
		Secrets: cfg.Secrets,
		EOL:     cfg.EOL,
	})

	logger.L().Info("starting scan",
		zap.String("target", abs),
		zap.Bool("offline", cfg.Offline),
		zap.Bool("secrets", cfg.Secrets),
		zap.Bool("eol", cfg.EOL),
	)
	result, err := engine.Scan(cmd.Context(), abs)
	if err != nil {
		return err
	}

	formats := report.ParseFormats(cfg.Report)
	return report.WriteAll(formats, result, cmd.OutOrStdout(), ".")
}

func newDBCommand(v *viper.Viper) *cobra.Command {
	dbCmd := &cobra.Command{
		Use:   "db",
		Short: "Manage the local vulnerability database",
	}

	updateCmd := &cobra.Command{
		Use:   "update [path]",
		Short: "Update NVD and OSV provider data",
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

	// Discover packages so OSV can fetch relevant advisories online.
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
	fmt.Fprintf(cmd.OutOrStdout(), "database ready: %d CVEs, %d advisories, %d secret rules, %d eol rows at %s\n",
		cves, adv, secrets, eols, expandPath(cfg.DBPath))
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
