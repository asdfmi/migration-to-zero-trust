package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	InterfaceName     string
	PrivateKey        wgtypes.Key
	Address           string
	GatewayPublicKey  string
	GatewayEndpoint   string
	AllowedCIDRs      []string
	PersistentKeepSec *int
}

func Apply(cfg Config) error {
	if os.Geteuid() != 0 {
		return errors.New("client must run as root to configure WireGuard")
	}
	if cfg.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	if cfg.GatewayPublicKey == "" || cfg.GatewayEndpoint == "" {
		return errors.New("gateway public key and endpoint are required")
	}

	link, err := ensureWireGuardLink(cfg.InterfaceName)
	if err != nil {
		return err
	}

	// Set IP address on interface
	if cfg.Address != "" {
		if err := setInterfaceAddress(link, cfg.Address); err != nil {
			return err
		}
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

	if err := client.ConfigureDevice(cfg.InterfaceName, wgCfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	if err := ensureRoutes(link, cfg.AllowedCIDRs); err != nil {
		return err
	}

	return nil
}

func Down(iface string) error {
	if iface == "" {
		return errors.New("interface name is required")
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("link lookup: %w", err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("link delete: %w", err)
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

func setInterfaceAddress(link netlink.Link, address string) error {
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("parse address %s: %w", address, err)
	}

	// Remove existing addresses
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	for _, existing := range addrs {
		if err := netlink.AddrDel(link, &existing); err != nil {
			return fmt.Errorf("delete address: %w", err)
		}
	}

	// Add new address
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add address %s: %w", address, err)
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
		if err := netlink.RouteReplace(&route); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			return fmt.Errorf("route[%d] add: %w", i, err)
		}
	}
	return nil
}

func buildConfig(cfg Config) (wgtypes.Config, error) {
	pubKey, err := wgtypes.ParseKey(cfg.GatewayPublicKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse gateway public key: %w", err)
	}
	endpoint, err := net.ResolveUDPAddr("udp", cfg.GatewayEndpoint)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse gateway endpoint: %w", err)
	}

	allowed := make([]net.IPNet, 0, len(cfg.AllowedCIDRs))
	for i, cidr := range cfg.AllowedCIDRs {
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

	if cfg.PersistentKeepSec != nil {
		ka := time.Duration(*cfg.PersistentKeepSec) * time.Second
		peerCfg.PersistentKeepaliveInterval = &ka
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &cfg.PrivateKey,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peerCfg},
	}

	return wgCfg, nil
}
