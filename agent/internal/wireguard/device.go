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

// Config holds WireGuard interface configuration.
type Config struct {
	InterfaceName     string
	PrivateKey        wgtypes.Key
	Enforcers         []EnforcerPeer
	PersistentKeepSec *int
}

// EnforcerPeer represents a single enforcer peer configuration.
type EnforcerPeer struct {
	TunnelIP          string // Client's IP for this enforcer's tunnel
	EnforcerPublicKey string
	EnforcerEndpoint  string
	AllowedCIDRs      []string // Resource CIDRs behind this enforcer
}

type State struct {
	InterfaceName string
	Exists        bool
	PeerCount     int
}

// Apply configures WireGuard interface with the given configuration.
// It creates the interface if needed, assigns IP addresses, configures peers, and sets up routes.
func Apply(cfg Config) error {
	// --- Validation ---
	if os.Geteuid() != 0 {
		return errors.New("client must run as root to configure WireGuard")
	}
	if cfg.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	if len(cfg.Enforcers) == 0 {
		return errors.New("at least one enforcer is required")
	}

	// --- Create or get WireGuard interface ---
	// Check if interface already exists; if not, create a new WireGuard interface.
	// This uses netlink to interact with the Linux network stack.
	link, err := netlink.LinkByName(cfg.InterfaceName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("link lookup: %w", err)
		}
		// Interface doesn't exist, create it
		attrs := netlink.NewLinkAttrs()
		attrs.Name = cfg.InterfaceName
		wgLink := &netlink.Wireguard{LinkAttrs: attrs}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return fmt.Errorf("link add: %w", err)
		}
		link = wgLink
	} else {
		// Interface exists, verify it's a WireGuard interface
		if link.Type() != "wireguard" {
			return fmt.Errorf("link %s exists but is not wireguard", cfg.InterfaceName)
		}
	}

	// --- Set tunnel IP addresses ---
	// Remove all existing addresses first, then add tunnel IPs from each enforcer.
	// Each enforcer assigns a tunnel IP to the client for communication through that enforcer.
	existingAddrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	for _, existing := range existingAddrs {
		if err := netlink.AddrDel(link, &existing); err != nil {
			return fmt.Errorf("delete address: %w", err)
		}
	}
	for _, enf := range cfg.Enforcers {
		if enf.TunnelIP == "" {
			continue
		}
		addr, err := netlink.ParseAddr(enf.TunnelIP)
		if err != nil {
			return fmt.Errorf("parse address %s: %w", enf.TunnelIP, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("add address %s: %w", enf.TunnelIP, err)
		}
	}

	// --- Bring interface up ---
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link set up: %w", err)
	}

	// --- Configure WireGuard peers ---
	// Convert our Config to wgtypes.Config and apply via wgctrl.
	// Each enforcer becomes a WireGuard peer with its public key, endpoint, and allowed IPs.
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl init: %w", err)
	}
	defer client.Close()

	var peers []wgtypes.PeerConfig
	for i, enf := range cfg.Enforcers {
		pubKey, err := wgtypes.ParseKey(enf.EnforcerPublicKey)
		if err != nil {
			return fmt.Errorf("enforcer[%d] parse public key: %w", i, err)
		}
		endpoint, err := net.ResolveUDPAddr("udp", enf.EnforcerEndpoint)
		if err != nil {
			return fmt.Errorf("enforcer[%d] parse endpoint: %w", i, err)
		}

		// Parse allowed CIDRs - these are the networks reachable through this enforcer
		allowed := make([]net.IPNet, 0, len(enf.AllowedCIDRs))
		for j, cidr := range enf.AllowedCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("enforcer[%d] allowed_ips[%d]: %w", i, j, err)
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

		peers = append(peers, peerCfg)
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &cfg.PrivateKey,
		ReplacePeers: true,
		Peers:        peers,
	}
	if err := client.ConfigureDevice(cfg.InterfaceName, wgCfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	// --- Setup routes ---
	// Add routes for all allowed CIDRs so traffic to protected resources goes through WireGuard.
	// Using more specific routes (/32) allows WireGuard to take priority over broader VPN routes.
	for _, enf := range cfg.Enforcers {
		for i, cidr := range enf.AllowedCIDRs {
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
	}

	return nil
}

// Down removes the WireGuard interface.
func Down(ifaceName string) error {
	if ifaceName == "" {
		return errors.New("interface name is required")
	}
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil // Already gone, nothing to do
		}
		return fmt.Errorf("link lookup: %w", err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("link delete: %w", err)
	}
	return nil
}

// ReadState returns the current state of the WireGuard interface.
func ReadState(ifaceName string) (State, error) {
	if ifaceName == "" {
		return State{}, errors.New("interface name is required")
	}
	_, err := netlink.LinkByName(ifaceName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return State{InterfaceName: ifaceName, Exists: false}, nil
		}
		return State{}, fmt.Errorf("link lookup: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return State{}, fmt.Errorf("wgctrl init: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(ifaceName)
	if err != nil {
		return State{}, fmt.Errorf("wg device: %w", err)
	}
	return State{
		InterfaceName: ifaceName,
		Exists:        true,
		PeerCount:     len(dev.Peers),
	}, nil
}
