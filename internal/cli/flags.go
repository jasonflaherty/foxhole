package cli

import (
	"fmt"

	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type flagGroup struct {
	title string
	fs    *pflag.FlagSet
}

func registerRootFlags(root *cobra.Command, v *viper.Viper) []flagGroup {
	scanFS := pflag.NewFlagSet("scan", pflag.ContinueOnError)
	scanFS.Bool("secrets", true, "enable secret scanning")
	scanFS.Bool("eol", true, "enable end-of-life checks")
	scanFS.Bool("misconfig", true, "enable Dockerfile misconfiguration checks")
	scanFS.Bool("licenses", true, "enable license risk checks")
	scanFS.Bool("enrich", true, "enrich vulns with KEV/EPSS")

	policyFS := pflag.NewFlagSet("policy", pflag.ContinueOnError)
	policyFS.String("fail-on", "", "fail CI if findings at or above severity (critical|high|medium|low|info|any)")
	policyFS.String("policy", "", "path to policy YAML (fail_on, kinds, ignore, suppressions)")
	policyFS.String("policy-dir", "", "merge all *.yaml policy files in directory (org policy packs)")
	policyFS.StringSlice("fail-on-kind", nil, "limit policy to finding kinds; repeatable")
	policyFS.String("max-db-age", "", "fail scan (exit 1) if vulnerability DB older than duration (e.g. 720h)")

	reportFS := pflag.NewFlagSet("report", pflag.ContinueOnError)
	reportFS.String("report", "console", "formats: console,json,markdown,html,sarif,junit,cyclonedx,spdx")
	reportFS.Bool("split-reports", false, "also write per-kind JSON (foxhole-vulns.json, …)")
	reportFS.Bool("archive", false, "write reports under archive/YYYY/MM/DD/")
	reportFS.String("archive-dir", "archive", "base directory for archived reports")
	reportFS.Bool("evidence", false, "write foxhole-evidence/ audit pack")
	reportFS.String("evidence-dir", "foxhole-evidence", "directory for evidence pack")
	reportFS.Bool("remediate", false, "write remediation suggestions (markdown+json)")
	reportFS.Bool("remediate-ai", false, "enrich remediation with OpenAI-compatible API")
	reportFS.Bool("triage", false, "write triage groups + suggested suppressions")
	reportFS.Bool("triage-ai", false, "enrich triage narratives with OpenAI-compatible API")

	notifyFS := pflag.NewFlagSet("notify", pflag.ContinueOnError)
	notifyFS.Bool("github", false, "open a GitHub issue with full scan summary")
	notifyFS.Bool("github-diff", false, "open/close GitHub issues vs last green scan")
	notifyFS.Bool("github-checks", false, "create a GitHub Check Run")
	notifyFS.Bool("teams", false, "post scan summary to Microsoft Teams webhook")
	notifyFS.Bool("slack", false, "post to Slack webhook")
	notifyFS.Bool("discord", false, "post to Discord webhook")
	notifyFS.Bool("email", false, "email scan summary via SMTP")
	notifyFS.Bool("webhook", false, "post JSON to FOXHOLE_WEBHOOK_URL")

	root.Flags().AddFlagSet(scanFS)
	root.Flags().AddFlagSet(policyFS)
	root.Flags().AddFlagSet(reportFS)
	root.Flags().AddFlagSet(notifyFS)

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
	_ = v.BindPFlag("evidence", root.Flags().Lookup("evidence"))
	_ = v.BindPFlag("evidence_dir", root.Flags().Lookup("evidence-dir"))
	_ = v.BindPFlag("triage", root.Flags().Lookup("triage"))
	_ = v.BindPFlag("triage_ai", root.Flags().Lookup("triage-ai"))

	return []flagGroup{
		{title: "Scan", fs: scanFS},
		{title: "Policy & CI", fs: policyFS},
		{title: "Reports & artifacts", fs: reportFS},
		{title: "Notifications", fs: notifyFS},
	}
}

func registerGlobalFlags(root *cobra.Command, v *viper.Viper) {
	root.PersistentFlags().String("db-path", config.DefaultDBPath(), "path to SQLite database")
	root.PersistentFlags().Bool("offline", false, "disable network access")
	root.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	root.PersistentFlags().String("nvd-api-key", "", "optional NVD API key")

	_ = v.BindPFlag("db_path", root.PersistentFlags().Lookup("db-path"))
	_ = v.BindPFlag("offline", root.PersistentFlags().Lookup("offline"))
	_ = v.BindPFlag("log_level", root.PersistentFlags().Lookup("log-level"))
	_ = v.BindPFlag("nvd_api_key", root.PersistentFlags().Lookup("nvd-api-key"))
}

func setGroupedHelp(cmd *cobra.Command, groups []flagGroup) {
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		out := c.OutOrStderr()
		fmt.Fprintf(out, "Usage:\n  %s\n", c.UseLine())
		if c.HasAvailableSubCommands() {
			fmt.Fprintln(out, "\nAvailable Commands:")
			for _, sub := range c.Commands() {
				if !sub.IsAvailableCommand() || sub.IsAdditionalHelpTopicCommand() {
					continue
				}
				fmt.Fprintf(out, "  %-12s %s\n", sub.Name(), sub.Short)
			}
		}
		for _, g := range groups {
			if g.fs == nil || !g.fs.HasFlags() {
				continue
			}
			fmt.Fprintf(out, "\n%s:\n", g.title)
			fmt.Fprint(out, g.fs.FlagUsages())
		}
		if c.HasAvailablePersistentFlags() {
			fmt.Fprintln(out, "\nGlobal:")
			fmt.Fprint(out, c.PersistentFlags().FlagUsages())
		}
		fmt.Fprintf(out, "\nUse \"%s [command] --help\" for more information about a command.\n", c.CommandPath())
		return nil
	})
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		out := c.OutOrStdout()
		if c.Long != "" {
			fmt.Fprintln(out, c.Long)
			fmt.Fprintln(out)
		} else if c.Short != "" {
			fmt.Fprintln(out, c.Short)
			fmt.Fprintln(out)
		}
		_ = c.Usage()
	})
}
