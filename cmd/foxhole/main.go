package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jasonflaherty/foxhole/internal/cli"
	"github.com/jasonflaherty/foxhole/internal/logger"
)

func main() {
	defer logger.Sync()
	root := cli.NewRootCommand()
	if err := root.Execute(); err != nil {
		code := cli.ExitCodeOf(err)
		var ee *cli.ExitError
		// Policy failures already print a detailed summary to stderr.
		if !errors.As(err, &ee) || ee.Code != 2 {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(code)
	}
}
