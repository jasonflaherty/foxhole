package main

import (
	"fmt"
	"os"

	"github.com/jasonflaherty/foxhole/internal/cli"
	"github.com/jasonflaherty/foxhole/internal/logger"
)

func main() {
	defer logger.Sync()
	root := cli.NewRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
