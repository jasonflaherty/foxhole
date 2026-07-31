package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jasonflaherty/foxhole/internal/archive"
	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/jasonflaherty/foxhole/internal/db"
	"github.com/jasonflaherty/foxhole/internal/diff"
	"github.com/jasonflaherty/foxhole/internal/evidence"
	"github.com/jasonflaherty/foxhole/internal/logger"
	"github.com/jasonflaherty/foxhole/internal/notify"
	"github.com/jasonflaherty/foxhole/internal/pluginadapt"
	"github.com/jasonflaherty/foxhole/internal/policy"
	"github.com/jasonflaherty/foxhole/internal/remediate"
	"github.com/jasonflaherty/foxhole/internal/report"
	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/internal/triage"
	"github.com/jasonflaherty/foxhole/pkg/plugin"
	"github.com/jasonflaherty/foxhole/pkg/provider/ghsa"
	"github.com/jasonflaherty/foxhole/pkg/provider/nvd"
	"github.com/jasonflaherty/foxhole/pkg/provider/osv"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

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
	result, err := newScanEngine(database, cfg).Scan(cmd.Context(), abs)
	if err != nil {
		_ = database.FinishScanHistory(cmd.Context(), histID, 0, "", "[]", "error")
		return err
	}

	reportPath, err := writeScanOutputs(cmd, cfg, result)
	if err != nil {
		_ = database.FinishScanHistory(cmd.Context(), histID, len(result.Findings), "", "[]", "error")
		return err
	}

	if err := writeRemediation(cmd, cfg, result); err != nil {
		return err
	}

	triageRep, err := writeTriage(cmd, cfg, result)
	if err != nil {
		return err
	}

	pol, err := loadScanPolicy(cfg, cmd)
	if err != nil {
		return err
	}
	decision := policy.Evaluate(pol, result.Findings)
	policy.WriteSuppressionWarnings(cmd.ErrOrStderr(), decision)

	if err := writeEvidence(cmd, cfg, result, pol, decision, database); err != nil {
		return err
	}

	flags := notifyFlagsFromCmd(cmd)
	prevFindings := loadGitHubDiffBaseline(cmd, database, abs, flags.GitHubDiff)

	snap, err := diff.SnapshotJSON(result.Findings)
	if err != nil {
		snap = "[]"
	}
	histStatus := "ok"
	if decision.Failed {
		histStatus = "policy_failed"
	}
	if err := database.FinishScanHistory(cmd.Context(), histID, len(result.Findings), reportPath, snap, histStatus); err != nil {
		logger.L().Warn("finish scan history failed", zap.Error(err))
	}

	runNotifications(cmd, database, abs, result, triageRep, prevFindings, flags)

	if decision.Failed {
		policy.Write(cmd.ErrOrStderr(), decision)
		return &ExitError{Code: decision.ExitCode(), Err: decision}
	}
	return nil
}

func newScanEngine(database *db.DB, cfg *config.Config) *scan.Engine {
	osvProv := osv.New(database, osv.WithOffline(cfg.Offline))
	nvdProv := nvd.New(database, nvd.WithOffline(cfg.Offline), nvd.WithAPIKey(cfg.NVDAPIKey))
	ghsaProv := ghsa.New(database)
	return scan.NewEngine(database, osvProv, nvdProv, ghsaProv).
		WithOptions(scan.EngineOptions{
			Secrets:   cfg.Secrets,
			EOL:       cfg.EOL,
			Misconfig: cfg.Misconfig,
			Licenses:  cfg.Licenses,
			Enrich:    cfg.Enrich,
		}).
		WithPlugins(pluginadapt.Runner{Reg: plugin.NewRegistry()})
}

func writeScanOutputs(cmd *cobra.Command, cfg *config.Config, result *scan.Result) (reportPath string, err error) {
	formats := report.ParseFormats(cfg.Report)
	if err := report.WriteAll(formats, result, cmd.OutOrStdout(), "."); err != nil {
		return "", err
	}
	if cfg.SplitReports {
		if err := report.WriteSplitJSON(result, ".", cmd.OutOrStdout()); err != nil {
			return "", fmt.Errorf("split reports: %w", err)
		}
	}
	doArchive, _ := cmd.Flags().GetBool("archive")
	if !doArchive {
		return "", nil
	}
	dir, err := archive.Write(cfg.ArchiveDir, result, result.FinishedAt)
	if err != nil {
		return "", fmt.Errorf("archive: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Archived to %s\n", dir)
	return dir, nil
}

func writeRemediation(cmd *cobra.Command, cfg *config.Config, result *scan.Result) error {
	if !cfg.Remediate && !cfg.RemediateAI {
		return nil
	}
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
	return nil
}

func writeTriage(cmd *cobra.Command, cfg *config.Config, result *scan.Result) (*triage.Report, error) {
	if !cfg.Triage && !cfg.TriageAI {
		return nil, nil
	}
	opts := triage.Options{AI: cfg.TriageAI, Options: remediate.FromEnv()}
	rep, err := triage.Generate(cmd.Context(), result, opts)
	if err != nil {
		return nil, fmt.Errorf("triage: %w", err)
	}
	mdFile, err := os.Create("foxhole-triage.md")
	if err != nil {
		return nil, err
	}
	if err := triage.WriteMarkdown(mdFile, rep); err != nil {
		_ = mdFile.Close()
		return nil, err
	}
	_ = mdFile.Close()
	jsonFile, err := os.Create("foxhole-triage.json")
	if err != nil {
		return nil, err
	}
	if err := triage.WriteJSON(jsonFile, rep); err != nil {
		_ = jsonFile.Close()
		return nil, err
	}
	_ = jsonFile.Close()
	fmt.Fprintln(cmd.OutOrStdout(), "wrote foxhole-triage.md\nwrote foxhole-triage.json")
	return rep, nil
}

func writeEvidence(cmd *cobra.Command, cfg *config.Config, result *scan.Result, pol policy.Policy, decision policy.Result, database *db.DB) error {
	if !cfg.Evidence {
		return nil
	}
	dir, err := evidence.Write(cmd.Context(), evidence.Input{
		Result:       result,
		Policy:       pol,
		Decision:     decision,
		Database:     database,
		MaxDBAge:     cfg.MaxDBAge,
		Image:        os.Getenv("FOXHOLE_IMAGE"),
		ImageDigest:  os.Getenv("FOXHOLE_IMAGE_DIGEST"),
		SplitReports: cfg.SplitReports,
		OutDir:       cfg.EvidenceDir,
	})
	if err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Evidence pack: %s\n", dir)
	return nil
}

type notifyFlagState struct {
	GitHub, GitHubDiff, Teams, Email, Slack, Discord, Webhook, GitHubChecks bool
}

func notifyFlagsFromCmd(cmd *cobra.Command) notifyFlagState {
	get := func(name string) bool {
		v, _ := cmd.Flags().GetBool(name)
		return v
	}
	return notifyFlagState{
		GitHub: get("github"), GitHubDiff: get("github-diff"), Teams: get("teams"),
		Email: get("email"), Slack: get("slack"), Discord: get("discord"),
		Webhook: get("webhook"), GitHubChecks: get("github-checks"),
	}
}

func loadGitHubDiffBaseline(cmd *cobra.Command, database *db.DB, abs string, enabled bool) map[string]scan.Finding {
	if !enabled {
		return nil
	}
	green, err := database.LastGreenScan(cmd.Context(), abs)
	if err != nil {
		logger.L().Warn("last green scan lookup failed", zap.Error(err))
		return nil
	}
	if green == nil {
		return nil
	}
	prev, _ := diff.SetFromJSON(green.FindingsJSON)
	return prev
}

func runNotifications(cmd *cobra.Command, database *db.DB, abs string, result *scan.Result, triageRep *triage.Report, prevFindings map[string]scan.Finding, flags notifyFlagState) {
	ncfg := notify.FromEnv()
	for _, n := range notify.SelectAll(ncfg, notify.Flags{
		GitHub: flags.GitHub, Teams: flags.Teams, Email: flags.Email,
		Slack: flags.Slack, Discord: flags.Discord, Webhook: flags.Webhook, GitHubChecks: flags.GitHubChecks,
	}) {
		if err := n.Notify(cmd.Context(), result); err != nil {
			logger.L().Warn("notify failed", zap.String("channel", n.Name()), zap.Error(err))
			fmt.Fprintf(cmd.ErrOrStderr(), "notify %s: %v\n", n.Name(), err)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Notified %s\n", n.Name())
		}
	}

	if !flags.GitHubDiff {
		return
	}
	gd := notify.GitHubDiffNotifier{
		Token:    ncfg.GitHubToken,
		Repo:     ncfg.GitHubRepo,
		Client:   ncfg.Client,
		DB:       database,
		Previous: prevFindings,
		Triage:   triageRep,
		Target:   abs,
	}
	if err := gd.Notify(cmd.Context(), result); err != nil {
		logger.L().Warn("notify failed", zap.String("channel", gd.Name()), zap.Error(err))
		fmt.Fprintf(cmd.ErrOrStderr(), "notify %s: %v\n", gd.Name(), err)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Notified %s\n", gd.Name())
	}
}
