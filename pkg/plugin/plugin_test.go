package plugin_test

import (
	"context"
	"io"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/scan"
	"github.com/jasonflaherty/foxhole/pkg/plugin"
)

type stubScanner struct{}

func (stubScanner) Name() string    { return "stub" }
func (stubScanner) Version() string { return "0.0.1" }
func (stubScanner) Scan(context.Context, string) ([]scan.Finding, error) {
	return nil, nil
}

type stubReporter struct{}

func (stubReporter) Name() string    { return "stub-report" }
func (stubReporter) Version() string { return "0.0.1" }
func (stubReporter) Format() string  { return "stub" }
func (stubReporter) Write(io.Writer, *scan.Result) error {
	return nil
}

func TestRegistry(t *testing.T) {
	r := plugin.NewRegistry()
	if err := r.RegisterScanner(stubScanner{}); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterReporter(stubReporter{}); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterScanner(stubScanner{}); err == nil {
		t.Fatal("expected duplicate error")
	}
	if len(r.Scanners()) != 1 || len(r.Reporters()) != 1 {
		t.Fatalf("unexpected counts")
	}
}
