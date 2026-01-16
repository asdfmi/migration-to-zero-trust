package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/agent/internal/config"
	"migration-to-zero-trust/agent/internal/connection"
	"migration-to-zero-trust/agent/internal/controlplane"
	"migration-to-zero-trust/agent/internal/wireguard"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type upOptions struct {
	ControlPlaneURL string
	Username        string
	Password        string
	InterfaceName   string
}

func NewUpCommand() *cobra.Command {
	opts := &upOptions{}

	cmd := &cobra.Command{
		Use:   "up",
		Short: "Login, fetch config, and apply WireGuard settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			boot, err := config.Load(config.Input{
				ControlPlaneURL: opts.ControlPlaneURL,
				Username:        opts.Username,
				Password:        opts.Password,
				InterfaceName:   opts.InterfaceName,
			})
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			cp := controlplane.New(boot.ControlPlaneURL)
			session, err := cp.Login(ctx, boot.Username, boot.Password)
			if err != nil {
				return err
			}

			privKey, _, err := wireguard.LoadOrGenerateKeyPair(config.KeyPathForInterface(boot.InterfaceName))
			if err != nil {
				return err
			}

			connPath := connection.PathForInterface(boot.InterfaceName)
			applyFn := makeApplyFunc(boot.ControlPlaneURL, boot.InterfaceName, privKey, connPath)

			// Initial apply
			cfg, err := cp.FetchConfig(ctx, session.Token)
			if err != nil {
				return err
			}
			if err := applyFn(cfg); err != nil {
				_ = wireguard.Down(boot.InterfaceName)
				return err
			}

			poller := &controlplane.Poller{
				Client:   cp,
				Username: boot.Username,
				Password: boot.Password,
				Interval: controlplane.DefaultPollInterval,
				OnChange: applyFn,
			}

			fmt.Fprintln(cmd.OutOrStdout(), "client is running; press Ctrl+C to stop")
			if err := poller.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				_ = wireguard.Down(boot.InterfaceName)
				return err
			}
			if err := wireguard.Down(boot.InterfaceName); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to remove interface: %v\n", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "client stopped")
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.ControlPlaneURL, "cp-url", "", "control plane base URL")
	cmd.Flags().StringVar(&opts.Username, "username", "", "client username")
	cmd.Flags().StringVar(&opts.Password, "password", "", "client password")
	cmd.Flags().StringVar(&opts.InterfaceName, "iface", "", "wireguard interface name")
	cmd.MarkFlagRequired("cp-url")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("password")

	return cmd
}

func makeApplyFunc(cpURL, ifaceName string, privKey wgtypes.Key, connPath string) func(controlplane.ClientConfig) error {
	return func(cfg controlplane.ClientConfig) error {
		if len(cfg.Enforcers) == 0 {
			return errors.New("no enforcers in client config")
		}

		var enforcers []wireguard.EnforcerPeer
		for _, enf := range cfg.Enforcers {
			if enf.EnforcerPublicKey == "" || enf.EnforcerEndpoint == "" {
				return errors.New("enforcer information is missing")
			}
			enforcers = append(enforcers, wireguard.EnforcerPeer{
				TunnelIP:          enf.TunnelIP,
				EnforcerPublicKey: enf.EnforcerPublicKey,
				EnforcerEndpoint:  enf.EnforcerEndpoint,
				AllowedCIDRs:      enf.AllowedCIDRs,
			})
		}

		if err := wireguard.Apply(wireguard.Config{
			InterfaceName: ifaceName,
			PrivateKey:    privKey,
			Enforcers:     enforcers,
		}); err != nil {
			return err
		}

		return connection.Save(connPath, connection.State{
			ControlPlaneURL: cpURL,
			InterfaceName:   ifaceName,
			Config:          cfg,
		})
	}
}
