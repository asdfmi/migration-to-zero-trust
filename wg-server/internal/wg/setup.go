package wg

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"migration-to-zero-trust/wg-server/internal/config"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Apply(cfg config.Config) error {
	if os.Geteuid() != 0 {
		return errors.New("wg-server must run as root")
	}

	link, err := ensureWireGuardLink(cfg.WG.Iface)
	if err != nil {
		return err
	}

	if err := ensureAddress(link, cfg.WG.Address); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link set up: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl init: %w", err)
	}
	defer client.Close()

	wgCfg, err := buildConfig(cfg)
	if err != nil {
		return err
	}

	if err := client.ConfigureDevice(cfg.WG.Iface, wgCfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	return nil
}

func ensureWireGuardLink(name string) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		if link.Type() != "wireguard" {
			return nil, fmt.Errorf("link %s exists but is not wireguard", name)
		}
		return link, nil
	}

	var notFound netlink.LinkNotFoundError
	if !errors.As(err, &notFound) {
		return nil, fmt.Errorf("link lookup: %w", err)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	wgLink := &netlink.Wireguard{LinkAttrs: attrs}
	if err := netlink.LinkAdd(wgLink); err != nil {
		return nil, fmt.Errorf("link add: %w", err)
	}

	return wgLink, nil
}

func ensureAddress(link netlink.Link, cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	addr := &netlink.Addr{IPNet: ipNet}
	if err := netlink.AddrAdd(link, addr); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return nil
		}
		return fmt.Errorf("addr add: %w", err)
	}

	return nil
}

func buildConfig(cfg config.Config) (wgtypes.Config, error) {
	privKey, err := wgtypes.ParseKey(cfg.WG.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse private key: %w", err)
	}

	peerCfgs := make([]wgtypes.PeerConfig, 0, len(cfg.WG.Peers))
	for i, peer := range cfg.WG.Peers {
		pubKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("peer[%d] public key: %w", i, err)
		}

		allowed := make([]net.IPNet, 0, len(peer.AllowedIPs))
		for j, cidr := range peer.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("peer[%d] allowed_ips[%d]: %w", i, j, err)
			}
			allowed = append(allowed, *ipNet)
		}

		peerCfgs = append(peerCfgs, wgtypes.PeerConfig{
			PublicKey:  pubKey,
			AllowedIPs: allowed,
		})
	}

	listenPort := cfg.WG.ListenPort

	return wgtypes.Config{
		PrivateKey:   &privKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        peerCfgs,
	}, nil
}
