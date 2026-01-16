package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/agent/internal/config"
	"migration-to-zero-trust/agent/internal/wireguard"
)

func NewKeygenCommand() *cobra.Command {
	var ifaceName string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate WireGuard key pair and display public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if ifaceName == "" {
				ifaceName = config.DefaultInterfaceName
			}

			keyPath := config.KeyPathForInterface(ifaceName)
			_, pubKey, err := wireguard.LoadOrGenerateKeyPair(keyPath)
			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout(), pubKey.String())
			return nil
		},
	}

	cmd.Flags().StringVar(&ifaceName, "iface", config.DefaultInterfaceName, "wireguard interface name")
	return cmd
}
