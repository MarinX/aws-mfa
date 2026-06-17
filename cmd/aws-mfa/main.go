package main

import "os"

// Set by GoReleaser at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	f := &flags{}
	rootCmd := buildRootCmd(f)
	rootCmd.AddCommand(buildSetupCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
