package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/agent/internal/config"
	"migration-to-zero-trust/agent/internal/connection"
	"migration-to-zero-trust/agent/internal/routing"
	"migration-to-zero-trust/agent/internal/wireguard"
)

func NewStatusCommand() *cobra.Command {
	var ifaceName string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current WireGuard status and configuration",
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

			wgState, err := wireguard.ReadState(iface)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()

			// Interface status
			fmt.Fprintf(out, "Interface:      %s\n", iface)
			if wgState.Exists {
				fmt.Fprintf(out, "Status:         connected\n")
				fmt.Fprintf(out, "Peers:          %d\n", wgState.PeerCount)
			} else {
				fmt.Fprintf(out, "Status:         disconnected\n")
			}

			// Enforcer configurations
			if len(conn.Config.Enforcers) > 0 {
				fmt.Fprintf(out, "\nEnforcers:\n")
				for i, enf := range conn.Config.Enforcers {
					fmt.Fprintf(out, "  [%d] %s\n", i+1, enf.EnforcerEndpoint)
					fmt.Fprintf(out, "      Tunnel IP: %s\n", enf.TunnelIP)
					fmt.Fprintf(out, "      CIDRs:     %s\n", strings.Join(enf.AllowedCIDRs, ", "))
				}
			}

			// Collect all CIDRs for routing check
			var allCIDRs []string
			for _, enf := range conn.Config.Enforcers {
				allCIDRs = append(allCIDRs, enf.AllowedCIDRs...)
			}

			// Routing status for allowed CIDRs
			if len(allCIDRs) > 0 {
				fmt.Fprintf(out, "\nResources:\n")
				routingStatus, err := routing.ResolvePreferredInterface(allCIDRs)
				if err != nil {
					fmt.Fprintf(out, "  (routing check failed: %v)\n", err)
				} else {
					for _, rs := range routingStatus {
						if rs.Preferred == iface {
							fmt.Fprintf(out, "  %s\n", rs.ResourceCIDR)
							fmt.Fprintf(out, "    %s ✓ (preferred)\n", iface)
							for _, r := range rs.Routes {
								if r.Interface != iface {
									fmt.Fprintf(out, "    %s: %s (overlap)\n", r.Interface, r.CIDR)
								}
							}
						} else if rs.Preferred != "" {
							fmt.Fprintf(out, "  %s\n", rs.ResourceCIDR)
							fmt.Fprintf(out, "    %s ⚠ (not preferred)\n", iface)
							fmt.Fprintf(out, "    %s: %s <- current route\n", rs.Preferred, rs.Routes[0].CIDR)
						} else {
							fmt.Fprintf(out, "  %s\n", rs.ResourceCIDR)
							fmt.Fprintf(out, "    no route ⚠\n")
						}
					}
				}
			}

			// Control plane info
			fmt.Fprintf(out, "\nControl Plane:  %s\n", conn.ControlPlaneURL)
			if !conn.UpdatedAt.IsZero() {
				fmt.Fprintf(out, "Last Updated:   %s\n", conn.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&ifaceName, "iface", config.DefaultInterfaceName, "wireguard interface name")
	return cmd
}
