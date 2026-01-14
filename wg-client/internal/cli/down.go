package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/wg-client/internal/state"
	"migration-to-zero-trust/wg-client/internal/wireguard"
)

func NewDownCommand() *cobra.Command {
	var ifaceName string

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop WireGuard interface and routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if ifaceName == "" {
				ifaceName = "wg0"
			}
			statePath := state.PathForInterface(ifaceName)
			st, err := state.Load(statePath)
			if err != nil {
				return err
			}
			iface := strings.TrimSpace(st.InterfaceName)
			if iface == "" {
				return errors.New("state is missing interface name; run `wg-client up` again")
			}
			if err := wireguard.Down(iface); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "wireguard interface removed")
			return nil
		},
	}

	cmd.Flags().StringVar(&ifaceName, "iface", "wg0", "wireguard interface name")
	return cmd
}
