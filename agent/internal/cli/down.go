package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/agent/internal/config"
	"migration-to-zero-trust/agent/internal/connection"
	"migration-to-zero-trust/agent/internal/wireguard"
)

func NewDownCommand() *cobra.Command {
	var ifaceName string

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop WireGuard interface and routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if ifaceName == "" {
				ifaceName = config.DefaultInterfaceName
			}
			connPath := connection.PathForInterface(ifaceName)
			conn, err := connection.Load(connPath)
			if err != nil {
				return err
			}
			iface := strings.TrimSpace(conn.InterfaceName)
			if iface == "" {
				return errors.New("connection info is missing interface name; run `agent up` again")
			}
			if err := wireguard.Down(iface); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "wireguard interface removed")
			return nil
		},
	}

	cmd.Flags().StringVar(&ifaceName, "iface", config.DefaultInterfaceName, "wireguard interface name")
	return cmd
}
