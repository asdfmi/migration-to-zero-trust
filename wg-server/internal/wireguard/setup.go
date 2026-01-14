package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"migration-to-zero-trust/wg-server/internal/controlplane"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Manager struct {
	iface      string
	listenPort int
	privateKey wgtypes.Key
	publicKey  wgtypes.Key
}

func NewManager(iface string, listenPort int, keyPair *KeyPair) (*Manager, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("wg-server must run as root")
	}

	return &Manager{
		iface:      iface,
		listenPort: listenPort,
		privateKey: keyPair.PrivateKey,
		publicKey:  keyPair.PublicKey,
	}, nil
}

func (m *Manager) PublicKey() string {
	return m.publicKey.String()
}

func (m *Manager) Setup(address string) error {
	link, err := ensureWireGuardLink(m.iface)
	if err != nil {
		return err
	}

	if err := ensureAddress(link, address); err != nil {
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

	listenPort := m.listenPort
	cfg := wgtypes.Config{
		PrivateKey: &m.privateKey,
		ListenPort: &listenPort,
	}

	if err := client.ConfigureDevice(m.iface, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	return nil
}

func (m *Manager) ApplyPeers(policies []controlplane.Policy) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl init: %w", err)
	}
	defer client.Close()

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

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers:        peerCfgs,
	}

	if err := client.ConfigureDevice(m.iface, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	return nil
}

func (m *Manager) Interface() string {
	return m.iface
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
