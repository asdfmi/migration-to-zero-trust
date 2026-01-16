package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"migration-to-zero-trust/enforcer/internal/controlplane"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Setup creates and configures the WireGuard interface.
func Setup(iface string, listenPort int, keyPair *KeyPair, address string) error {
	if os.Geteuid() != 0 {
		return errors.New("enforcer must run as root")
	}

	// --- Create or get WireGuard interface ---
	var link netlink.Link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("link lookup: %w", err)
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = iface
		wgLink := &netlink.Wireguard{LinkAttrs: attrs}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return fmt.Errorf("link add: %w", err)
		}
		link = wgLink
	} else {
		if link.Type() != "wireguard" {
			return fmt.Errorf("link %s exists but is not wireguard", iface)
		}
	}

	// --- Set tunnel IP address ---
	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	ipNet.IP = ip // ParseCIDR returns network address in ipNet.IP; use the host address instead
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("addr add: %w", err)
		}
	}

	// --- Bring interface up ---
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link set up: %w", err)
	}

	// --- Configure WireGuard device ---
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl init: %w", err)
	}
	defer client.Close()

	cfg := wgtypes.Config{
		PrivateKey: &keyPair.PrivateKey,
		ListenPort: &listenPort,
	}
	if err := client.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	return nil
}

// ApplyPeers updates WireGuard peers based on the given policies.
func ApplyPeers(iface string, policies []controlplane.Policy) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl init: %w", err)
	}
	defer client.Close()

	// --- Build peer configs from policies ---
	peerCfgs := make([]wgtypes.PeerConfig, 0, len(policies))
	for _, policy := range policies {
		if policy.WGPublicKey == "" {
			continue
		}

		pubKey, err := wgtypes.ParseKey(policy.WGPublicKey)
		if err != nil {
			return fmt.Errorf("parse public key for client %s: %w", policy.ClientID, err)
		}

		allowed := make([]net.IPNet, 0, len(policy.AllowedIPs))
		for _, cidr := range policy.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("parse allowed_ips for client %s: %w", policy.ClientID, err)
			}
			allowed = append(allowed, *ipNet)
		}

		peerCfgs = append(peerCfgs, wgtypes.PeerConfig{
			PublicKey:         pubKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        allowed,
		})
	}

	// --- Apply peer configuration ---
	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peerCfgs,
	}
	if err := client.ConfigureDevice(iface, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	return nil
}
