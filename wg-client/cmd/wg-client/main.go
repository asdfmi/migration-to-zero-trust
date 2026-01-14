package main

import (
	"os"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/wg-client/internal/cli"
)

func main() {
	root := &cobra.Command{
		Use:   "wg-client",
		Short: "WireGuard client managed by control plane",
	}

	root.AddCommand(
		cli.NewUpCommand(),
		cli.NewDownCommand(),
		cli.NewStatusCommand(),
		cli.NewResourcesCommand(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
