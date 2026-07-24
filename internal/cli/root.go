package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/archive"
	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/diff"
	"github.com/jasonflaherty/foxhole/internal/logger"
	"github.com/jasonflaherty/foxhole/internal/notify"
	"github.com/jasonflaherty/foxhole/internal/pluginadapt"
	"github.com/jasonflaherty/foxhole/internal/policy"
	"github.com/jasonflaherty/foxhole/internal/remediate"
	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/seeds"
	"github.com/jasonflaherty/foxhole/internal/version"
	"github.com/jasonflaherty/foxhole/pkg/plugin"
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
	root.Flags().String("report", "console", "report formats: console,json,markdown,html,sarif,junit,cyclonedx,spdx")
	root.Flags().Bool("secrets", true, "enable secret scanning")
	root.Flags().Bool("eol", true, "enable end-of-life checks")
	root.Flags().Bool("misconfig", true, "enable Dockerfile misconfiguration checks")
	root.Flags().Bool("licenses", true, "enable license risk checks")
	root.Flags().Bool("enrich", true, "enrich vulns with KEV/EPSS")
	root.Flags().Bool("archive", false, "write reports under archive/YYYY/MM/DD/")
	root.Flags().String("archive-dir", "archive", "base directory for archived reports")
	root.Flags().Bool("github", false, "open a GitHub issue with scan summary")
	root.Flags().Bool("teams", false, "post scan summary to Microsoft Teams webhook")
	root.Flags().Bool("email", false, "email scan summary via SMTP")
	root.Flags().Bool("slack", false, "post to Slack webhook")
	root.Flags().Bool("discord", false, "post to Discord webhook")
	root.Flags().Bool("webhook", false, "post JSON to FOXHOLE_WEBHOOK_URL")
	root.Flags().Bool("github-checks", false, "create a GitHub Check Run")
	root.Flags().Bool("remediate", false, "write remediation suggestions (markdown+json)")
	root.Flags().Bool("remediate-ai", false, "enrich remediation with OpenAI-compatible API")
	root.Flags().String("fail-on", "", "fail CI if findings at or above severity (critical|high|medium|low|info|any)")
	root.Flags().String("policy", "", "path to policy YAML (fail_on, kinds, ignore, suppressions)")
	root.Flags().String("policy-dir", "", "merge all *.yaml policy files in directory (org policy packs)")
	root.Flags().StringSlice("fail-on-kind", nil, "limit policy to finding kinds; repeatable")
	root.Flags().Bool("split-reports", false, "also write per-kind JSON: foxhole-vulns.json, foxhole-secrets.json, …")
	root.Flags().String("max-db-age", "", "fail scan (exit 1) if vulnerability DB older than duration (e.g. 720h); empty disables")

	_ = v.BindPFlag("db_path", root.PersistentFlags().Lookup("db-path"))
	_ = v.BindPFlag("offline", root.PersistentFlags().Lookup("offline"))
	_ = v.BindPFlag("log_level", root.PersistentFlags().Lookup("log-level"))
	_ = v.BindPFlag("nvd_api_key", root.PersistentFlags().Lookup("nvd-api-key"))
	_ = v.BindPFlag("report", root.Flags().Lookup("report"))
	_ = v.BindPFlag("secrets", root.Flags().Lookup("secrets"))
	_ = v.BindPFlag("eol", root.Flags().Lookup("eol"))
	_ = v.BindPFlag("misconfig", root.Flags().Lookup("misconfig"))
	_ = v.BindPFlag("licenses", root.Flags().Lookup("licenses"))
	_ = v.BindPFlag("enrich", root.Flags().Lookup("enrich"))
	_ = v.BindPFlag("archive_dir", root.Flags().Lookup("archive-dir"))
	_ = v.BindPFlag("fail_on", root.Flags().Lookup("fail-on"))
	_ = v.BindPFlag("policy", root.Flags().Lookup("policy"))
	_ = v.BindPFlag("policy_dir", root.Flags().Lookup("policy-dir"))
	_ = v.BindPFlag("remediate", root.Flags().Lookup("remediate"))
	_ = v.BindPFlag("remediate_ai", root.Flags().Lookup("remediate-ai"))
	_ = v.BindPFlag("split_reports", root.Flags().Lookup("split-reports"))
	_ = v.BindPFlag("max_db_age", root.Flags().Lookup("max-db-age"))

	root.AddCommand(newDBCommand(v))
	root.AddCommand(newVersionCommand())
	root.AddCommand(newHistoryCommand(v))
	root.AddCommand(newDiffCommand(v))
	root.AddCommand(newServeCommand(v))
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

	if err := checkDBFreshness(cmd, database, cfg.MaxDBAge); err != nil {
		return err
	}

	osvProv := osv.New(database, osv.WithOffline(cfg.Offline))
	nvdProv := nvd.New(database, nvd.WithOffline(cfg.Offline), nvd.WithAPIKey(cfg.NVDAPIKey))
	ghsaProv := ghsa.New(database)
	engine := scan.NewEngine(database, osvProv, nvdProv, ghsaProv).
		WithOptions(scan.EngineOptions{
			Secrets:   cfg.Secrets,
			EOL:       cfg.EOL,
			Misconfig: cfg.Misconfig,
			Licenses:  cfg.Licenses,
			Enrich:    cfg.Enrich,
		}).
		WithPlugins(pluginadapt.Runner{Reg: plugin.NewRegistry()})

	doArchive, _ := cmd.Flags().GetBool("archive")
	doGitHub, _ := cmd.Flags().GetBool("github")
	doTeams, _ := cmd.Flags().GetBool("teams")
	doEmail, _ := cmd.Flags().GetBool("email")
	doSlack, _ := cmd.Flags().GetBool("slack")
	doDiscord, _ := cmd.Flags().GetBool("discord")
	doWebhook, _ := cmd.Flags().GetBool("webhook")
	doChecks, _ := cmd.Flags().GetBool("github-checks")

	histID, err := database.StartScanHistory(cmd.Context(), abs)
	if err != nil {
		return fmt.Errorf("scan history: %w", err)
	}

	logger.L().Info("starting scan",
		zap.String("target", abs),
		zap.Bool("offline", cfg.Offline),
		zap.Bool("secrets", cfg.Secrets),
		zap.Bool("eol", cfg.EOL),
	)
	result, err := engine.Scan(cmd.Context(), abs)
	if err != nil {
		_ = database.FinishScanHistory(cmd.Context(), histID, 0, "", "[]", "error")
		return err
	}

	formats := report.ParseFormats(cfg.Report)
	if err := report.WriteAll(formats, result, cmd.OutOrStdout(), "."); err != nil {
		_ = database.FinishScanHistory(cmd.Context(), histID, len(result.Findings), "", "[]", "error")
		return err
	}

	if cfg.SplitReports {
		if err := report.WriteSplitJSON(result, ".", cmd.OutOrStdout()); err != nil {
			_ = database.FinishScanHistory(cmd.Context(), histID, len(result.Findings), "", "[]", "error")
			return fmt.Errorf("split reports: %w", err)
		}
	}

	reportPath := ""
	if doArchive {
		dir, err := archive.Write(cfg.ArchiveDir, result, result.FinishedAt)
		if err != nil {
			_ = database.FinishScanHistory(cmd.Context(), histID, len(result.Findings), "", "[]", "error")
			return fmt.Errorf("archive: %w", err)
		}
		reportPath = dir
		fmt.Fprintf(cmd.OutOrStdout(), "Archived to %s\n", dir)
	}

	if cfg.Remediate || cfg.RemediateAI {
		opts := remediate.FromEnv()
		opts.AI = cfg.RemediateAI
		rep, err := remediate.Generate(cmd.Context(), result, opts)
		if err != nil {
			return fmt.Errorf("remediate: %w", err)
		}
		mdPath := "foxhole-remediation.md"
		jsonPath := "foxhole-remediation.json"
		mdFile, err := os.Create(mdPath)
		if err != nil {
			return err
		}
		if err := remediate.WriteMarkdown(mdFile, rep); err != nil {
			_ = mdFile.Close()
			return err
		}
		_ = mdFile.Close()
		jsonFile, err := os.Create(jsonPath)
		if err != nil {
			return err
		}
		if err := remediate.WriteJSON(jsonFile, rep); err != nil {
			_ = jsonFile.Close()
			return err
		}
		_ = jsonFile.Close()
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\nwrote %s\n", mdPath, jsonPath)
	}

	snap, err := diff.SnapshotJSON(result.Findings)
	if err != nil {
		snap = "[]"
	}
	if err := database.FinishScanHistory(cmd.Context(), histID, len(result.Findings), reportPath, snap, "ok"); err != nil {
		logger.L().Warn("finish scan history failed", zap.Error(err))
	}

	for _, n := range notify.SelectAll(notify.FromEnv(), notify.Flags{
		GitHub: doGitHub, Teams: doTeams, Email: doEmail,
		Slack: doSlack, Discord: doDiscord, Webhook: doWebhook, GitHubChecks: doChecks,
	}) {
		if err := n.Notify(cmd.Context(), result); err != nil {
			logger.L().Warn("notify failed", zap.String("channel", n.Name()), zap.Error(err))
			fmt.Fprintf(cmd.ErrOrStderr(), "notify %s: %v\n", n.Name(), err)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Notified %s\n", n.Name())
		}
	}

	pol, err := loadScanPolicy(cfg, cmd)
	if err != nil {
		return err
	}
	decision := policy.Evaluate(pol, result.Findings)
	policy.WriteSuppressionWarnings(cmd.ErrOrStderr(), decision)
	if decision.Failed {
		policy.Write(cmd.ErrOrStderr(), decision)
		return &ExitError{Code: decision.ExitCode(), Err: decision}
	}
	return nil
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
