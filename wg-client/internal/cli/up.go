package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"migration-to-zero-trust/wg-client/internal/config"
	"migration-to-zero-trust/wg-client/internal/controlplane"
	"migration-to-zero-trust/wg-client/internal/state"
	"migration-to-zero-trust/wg-client/internal/syncer"
	"migration-to-zero-trust/wg-client/internal/wireguard"
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

			privKey, pubKey, err := wireguard.EnsureKeyPair(config.KeyPathForInterface(boot.InterfaceName))
			if err != nil {
				return err
			}
			if err := cp.UpdatePublicKey(ctx, session.Token, pubKey.String()); err != nil {
				return err
			}

			cfg, err := cp.FetchConfig(ctx, session.Token)
			if err != nil {
				return err
			}
			if err := syncer.Apply(boot.InterfaceName, privKey, cfg); err != nil {
				_ = wireguard.Down(boot.InterfaceName)
				return err
			}
			statePath := state.PathForInterface(boot.InterfaceName)
			if err := state.Save(statePath, state.State{
				ControlPlaneURL: boot.ControlPlaneURL,
				InterfaceName:   boot.InterfaceName,
				Config:          cfg,
			}); err != nil {
				_ = wireguard.Down(boot.InterfaceName)
				return err
			}

			poller := &syncer.Poller{
				ControlPlane:    cp,
				ControlPlaneURL: boot.ControlPlaneURL,
				Username:        boot.Username,
				Password:        boot.Password,
				Interface:       boot.InterfaceName,
				PrivateKey:      privKey,
				Interval:        config.DefaultPollInterval,
				StatePath:       statePath,
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
