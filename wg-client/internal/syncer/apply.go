package syncer

import (
	"errors"

	"migration-to-zero-trust/wg-client/internal/controlplane"
	"migration-to-zero-trust/wg-client/internal/wireguard"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Apply(iface string, privateKey wgtypes.Key, cfg controlplane.ClientConfig) error {
	if cfg.GatewayPublicKey == "" || cfg.GatewayEndpoint == "" {
		return errors.New("gateway information is missing")
	}
	wgCfg := wireguard.Config{
		InterfaceName:    iface,
		PrivateKey:       privateKey,
		Address:          cfg.Address,
		GatewayPublicKey: cfg.GatewayPublicKey,
		GatewayEndpoint:  cfg.GatewayEndpoint,
		AllowedCIDRs:     cfg.AllowedCIDRs,
	}
	return wireguard.Apply(wgCfg)
}
