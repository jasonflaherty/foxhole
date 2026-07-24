// Package policy evaluates scan findings against fail-on rules for CI gates.
package policy

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jasonflaherty/foxhole/internal/scan"
)

// ExitPolicy is the process exit code when a policy gate fails.
const ExitPolicy = 2

// Enabled reports whether the policy will evaluate findings.
func (p Policy) Enabled() bool {
	s := normalizeFailOn(p.FailOn)
	return s != "" && s != "none"
}

// Result is the outcome of Evaluate.
type Result struct {
	Failed     bool
	Violations []scan.Finding
	Message    string
	UsedSupp   []Suppression // suppressions that matched findings
}

// Error implements error when the policy gate fails.
func (r Result) Error() string {
	if r.Message != "" {
		return r.Message
	}
	return fmt.Sprintf("policy failed: %d finding(s)", len(r.Violations))
}

// ExitCode returns ExitPolicy when failed, else 0.
func (r Result) ExitCode() int {
	if r.Failed {
		return ExitPolicy
	}
	return 0
}

// Evaluate applies the policy to scan findings.
func Evaluate(p Policy, findings []scan.Finding) Result {
	return EvaluateAt(p, findings, time.Now().UTC())
}

// EvaluateAt is Evaluate with an explicit clock (for tests).
func EvaluateAt(p Policy, findings []scan.Finding, now time.Time) Result {
	if !p.Enabled() {
		return Result{}
	}

	threshold := normalizeFailOn(p.FailOn)
	kindSet := make(map[string]struct{}, len(p.Kinds))
	for _, k := range p.Kinds {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" {
			kindSet[k] = struct{}{}
		}
	}
	active, _ := ActiveSuppressions(p, now)
	used := map[string]Suppression{}

	var violations []scan.Finding
	for _, f := range findings {
		if s, skip := active[f.ID()]; skip {
			used[f.ID()] = s
			continue
		}
		if len(kindSet) > 0 {
			if _, ok := kindSet[string(f.Kind)]; !ok {
				continue
			}
		}
		if matchesThreshold(threshold, f.Severity) {
			violations = append(violations, f)
		}
	}

	var usedList []Suppression
	for _, s := range used {
		usedList = append(usedList, s)
	}

	if len(violations) == 0 {
		return Result{UsedSupp: usedList}
	}

	label := threshold
	if threshold == "any" {
		label = "any severity"
	}
	return Result{
		Failed:     true,
		Violations: violations,
		Message:    fmt.Sprintf("policy failed: %d finding(s) at or above %s", len(violations), label),
		UsedSupp:   usedList,
	}
}

// Write summarizes violations for humans / CI logs.
func Write(w io.Writer, r Result) {
	if !r.Failed {
		return
	}
	fmt.Fprintln(w, r.Message)
	limit := len(r.Violations)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		f := r.Violations[i]
		fmt.Fprintf(w, "  - [%s] %s (%s): %s\n",
			strings.ToUpper(NormalizeSeverity(f.Severity)), f.ID(), f.Kind, f.Summary)
	}
	if len(r.Violations) > limit {
		fmt.Fprintf(w, "  - …and %d more\n", len(r.Violations)-limit)
	}
}

// WriteSuppressionWarnings prints active suppressions that matched findings.
func WriteSuppressionWarnings(w io.Writer, r Result) {
	for _, s := range r.UsedSupp {
		if s.Ticket != "" || s.Until != "" {
			fmt.Fprintf(w, "suppressed %s (ticket=%s until=%s): %s\n", s.ID, s.Ticket, s.Until, s.Reason)
		}
	}
}

// NormalizeSeverity maps free-form severity strings to a canonical token.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return "critical"
	case "high":
		return "high"
	case "medium", "med", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "negligible":
		return "info"
	default:
		return "unknown"
	}
}

func normalizeFailOn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "none", "off", "false":
		return "none"
	case "any", "all", "true":
		return "any"
	case "critical", "crit", "high", "medium", "med", "moderate", "low", "info":
		return NormalizeSeverity(s)
	default:
		return NormalizeSeverity(s)
	}
}

func severityRank(s string) int {
	switch NormalizeSeverity(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func matchesThreshold(threshold, findingSeverity string) bool {
	if threshold == "any" {
		return true
	}
	if threshold == "none" {
		return false
	}
	return severityRank(findingSeverity) >= severityRank(threshold)
}

// Merge overlays CLI/env overrides onto a base policy (non-empty wins).
func Merge(base Policy, failOn string, kinds []string) Policy {
	out := base
	if strings.TrimSpace(failOn) != "" {
		out.FailOn = failOn
	}
	if len(kinds) > 0 {
		out.Kinds = append([]string(nil), kinds...)
	}
	return out
}
