// Package npmscanner implements a Scanner plugin for Node.js npm packages.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/jasonflaherty/foxhole/pkg/sdk/scanner"
)

// NPMScanner discovers npm packages in a project.
type NPMScanner struct {
	cfg scanner.ScannerConfig
}

// NewNPMScanner creates a new npm scanner instance.
func NewNPMScanner() *NPMScanner {
	return &NPMScanner{
		cfg: scanner.ScannerConfig{
			Enabled: true,
		},
	}
}

// Metadata returns plugin information.
func (s *NPMScanner) Metadata() scanner.ScannerMetadata {
	return scanner.ScannerMetadata{
		ID:          "npm-scanner",
		Name:        "Node.js NPM Scanner",
		Version:     "0.1.0",
		Description: "Discovers npm packages from package.json and package-lock.json",
		Kind:        "packager",
		Languages:   []string{"JavaScript", "TypeScript"},
		Author:      "Foxhole Community",
		Repository:  "https://github.com/foxhole-plugins/npm-scanner",
	}
}

// Detect checks if npm manifest files exist.
func (s *NPMScanner) Detect(ctx context.Context, fsys fs.FS, path string) (bool, error) {
	_, err := fs.Stat(fsys, "package.json")
	return err == nil, nil
}

// packageJSON represents a minimal package.json structure.
type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Scan discovers npm packages from package.json.
func (s *NPMScanner) Scan(ctx context.Context, fsys fs.FS, path string) ([]scanner.Package, error) {
	var packages []scanner.Package

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "dist" || d.Name() == "build" {
				return filepath.SkipDir
			}

			for _, excluded := range s.cfg.ExcludeDirs {
				if strings.Contains(p, excluded) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if d.Name() != "package.json" {
			return nil
		}

		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil
		}

		var pkg packageJSON
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil
		}

		for name, version := range pkg.Dependencies {
			packages = append(packages, scanner.Package{
				Ecosystem: "npm",
				Name:      name,
				Version:   version,
				Path:      filepath.Dir(p),
			})
		}

		for name, version := range pkg.DevDependencies {
			packages = append(packages, scanner.Package{
				Ecosystem: "npm",
				Name:      name,
				Version:   version,
				Path:      filepath.Dir(p),
			})
		}

		return nil
	})

	return packages, err
}

// Configure applies settings to the scanner.
func (s *NPMScanner) Configure(ctx context.Context, cfg scanner.ScannerConfig) error {
	s.cfg = cfg
	return nil
}

// Close performs cleanup.
func (s *NPMScanner) Close(ctx context.Context) error {
	return nil
}

func main() {
	scanner := NewNPMScanner()
	fmt.Println("NPM Scanner Plugin")
	fmt.Printf("Name: %s\n", scanner.Metadata().Name)
}
