package wireguard

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type State struct {
	InterfaceName string
	Exists        bool
	PeerCount     int
}

func ReadState(iface string) (State, error) {
	if iface == "" {
		return State{}, errors.New("interface name is required")
	}
	_, err := netlink.LinkByName(iface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return State{InterfaceName: iface, Exists: false}, nil
		}
		return State{}, fmt.Errorf("link lookup: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		return State{}, fmt.Errorf("wgctrl init: %w", err)
	}
	defer client.Close()

	dev, err := client.Device(iface)
	if err != nil {
		return State{}, fmt.Errorf("wg device: %w", err)
	}
	return State{
		InterfaceName: iface,
		Exists:        true,
		PeerCount:     len(dev.Peers),
	}, nil
}
