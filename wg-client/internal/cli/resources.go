package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/wg-client/internal/state"
)

func NewResourcesCommand() *cobra.Command {
	var ifaceName string

	cmd := &cobra.Command{
		Use:   "resources",
		Short: "List allowed resources (CIDRs)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if ifaceName == "" {
				ifaceName = "wg0"
			}
			statePath := state.PathForInterface(ifaceName)
			st, err := state.Load(statePath)
			if err != nil {
				return err
			}

			if len(st.Config.AllowedCIDRs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no allowed CIDRs")
				return nil
			}
			for _, cidr := range st.Config.AllowedCIDRs {
				fmt.Fprintln(cmd.OutOrStdout(), cidr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&ifaceName, "iface", "wg0", "wireguard interface name")
	return cmd
}
