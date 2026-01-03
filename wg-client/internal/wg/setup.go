package wg

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"migration-to-zero-trust/wg-client/internal/config"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Apply(cfg config.Config) error {
	if os.Geteuid() != 0 {
		return errors.New("wg-client must run as root")
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

	if err := ensureRoutes(link, cfg.WG.AllowedIPs); err != nil {
		return err
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

func ensureRoutes(link netlink.Link, allowed []string) error {
	for i, cidr := range allowed {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("route[%d] parse: %w", i, err)
		}

		route := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       ipNet,
		}
		if err := netlink.RouteAdd(&route); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			return fmt.Errorf("route[%d] add: %w", i, err)
		}
	}

	return nil
}

func buildConfig(cfg config.Config) (wgtypes.Config, error) {
	privKey, err := wgtypes.ParseKey(cfg.WG.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse private key: %w", err)
	}

	pubKey, err := wgtypes.ParseKey(cfg.WG.ServerKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse server public key: %w", err)
	}

	endpoint, err := net.ResolveUDPAddr("udp", cfg.WG.ServerEndpoint)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse server endpoint: %w", err)
	}

	allowed := make([]net.IPNet, 0, len(cfg.WG.AllowedIPs))
	for i, cidr := range cfg.WG.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("allowed_ips[%d]: %w", i, err)
		}
		allowed = append(allowed, *ipNet)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		Endpoint:          endpoint,
		AllowedIPs:        allowed,
		ReplaceAllowedIPs: true,
	}

	if cfg.WG.KeepaliveSec != nil {
		ka := time.Duration(*cfg.WG.KeepaliveSec) * time.Second
		peerCfg.PersistentKeepaliveInterval = &ka
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &privKey,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peerCfg},
	}

	if cfg.WG.ListenPort > 0 {
		lp := cfg.WG.ListenPort
		wgCfg.ListenPort = &lp
	}

	return wgCfg, nil
}
