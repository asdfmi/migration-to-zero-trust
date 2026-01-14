package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/wg-client/internal/state"
	"migration-to-zero-trust/wg-client/internal/wireguard"
)

func NewStatusCommand() *cobra.Command {
	var ifaceName string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current WireGuard status",
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
			wgState, err := wireguard.ReadState(iface)
			if err != nil {
				return err
			}
			if !wgState.Exists {
				fmt.Fprintln(cmd.OutOrStdout(), "interface not found")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "interface=%s peers=%d\n", wgState.InterfaceName, wgState.PeerCount)
			return nil
		},
	}

	cmd.Flags().StringVar(&ifaceName, "iface", "wg0", "wireguard interface name")
	return cmd
}
