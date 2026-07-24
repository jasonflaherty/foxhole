package cli_test

import (
	"errors"
	"testing"

	"github.com/jasonflaherty/foxhole/internal/cli"
)

func TestExitCodeOf(t *testing.T) {
	t.Parallel()
	if cli.ExitCodeOf(nil) != 0 {
		t.Fatal("nil")
	}
	if cli.ExitCodeOf(errors.New("boom")) != 1 {
		t.Fatal("generic")
	}
	err := &cli.ExitError{Code: 2, Err: errors.New("policy")}
	if cli.ExitCodeOf(err) != 2 {
		t.Fatal("exit error")
	}
	if cli.ExitCodeOf(errors.Join(errors.New("outer"), err)) != 2 {
		t.Fatal("wrapped")
	}
	if err.Error() != "policy" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("unwrap")
	}
}
