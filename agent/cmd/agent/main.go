package main

import (
	"os"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/agent/internal/cli"
)

func main() {
	root := &cobra.Command{
		Use:   "agent",
		Short: "Zero Trust agent managed by control plane",
	}

	root.AddCommand(
		cli.NewKeygenCommand(),
		cli.NewUpCommand(),
		cli.NewDownCommand(),
		cli.NewStatusCommand(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
