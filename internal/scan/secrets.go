package scan

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jasonflaherty/foxhole/internal/db"
)

var secretSkipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, ".foxhole": {},
	"bin": {}, "dist": {}, "build": {}, ".cursor": {},
}

var secretSkipExt = map[string]struct{}{
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".webp": {}, ".ico": {},
	".pdf": {}, ".zip": {}, ".tar": {}, ".gz": {}, ".woff": {}, ".woff2": {},
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".db": {},
}

// SecretsScanner finds hardcoded secrets using DB rules.
type SecretsScanner struct {
	store *db.DB
}

// NewSecretsScanner creates a secrets scanner.
func NewSecretsScanner(store *db.DB) *SecretsScanner {
	return &SecretsScanner{store: store}
}

type compiledRule struct {
	rule db.SecretRule
	re   *regexp.Regexp
}

// Scan walks root and applies enabled secret rules.
func (s *SecretsScanner) Scan(ctx context.Context, root string) ([]Finding, error) {
	rules, err := s.store.ListSecretRules(ctx)
	if err != nil {
		return nil, err
	}
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledRule{rule: r, re: re})
	}
	if len(compiled) == 0 {
		return nil, nil
	}

	var findings []Finding
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			if _, skip := secretSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if _, skip := secretSkipExt[ext]; skip {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 1<<20 { // skip >1MiB
			return nil
		}
		founds, err := scanFileForSecrets(path, root, compiled)
		if err != nil {
			return nil // skip unreadable files
		}
		findings = append(findings, founds...)
		return nil
	})
	return findings, err
}

func scanFileForSecrets(path, root string, rules []compiledRule) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	rel := path
	if r, err := filepath.Rel(root, path); err == nil {
		rel = r
	}

	var out []Finding
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for _, cr := range rules {
			if !cr.re.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Kind:     KindSecret,
				Path:     rel,
				Line:     lineNo,
				RuleID:   cr.rule.ID,
				Summary:  fmt.Sprintf("%s matched", cr.rule.Name),
				Severity: cr.rule.Severity,
				Source:   "secrets",
			})
		}
	}
	return out, sc.Err()
}
