package config

import (
	"errors"
	"strings"
	"time"
)

const (
	DefaultInterfaceName = "wg0"
	DefaultPollInterval  = 15 * time.Second
	DefaultDir           = "/var/lib/migration-to-zero-trust"
)

func KeyPathForInterface(ifaceName string) string {
	if ifaceName == "" {
		ifaceName = DefaultInterfaceName
	}
	return DefaultDir + "/" + ifaceName + ".key"
}

type Input struct {
	ControlPlaneURL string
	Username        string
	Password        string
	InterfaceName   string
}

type Bootstrap struct {
	ControlPlaneURL string
	Username        string
	Password        string
	InterfaceName   string
}

func Load(input Input) (Bootstrap, error) {
	cpURL := strings.TrimSpace(input.ControlPlaneURL)
	user := strings.TrimSpace(input.Username)
	pass := strings.TrimSpace(input.Password)
	iface := strings.TrimSpace(input.InterfaceName)

	if cpURL == "" || user == "" || pass == "" {
		return Bootstrap{}, errors.New("control plane url, username, password are required")
	}
	if iface == "" {
		iface = DefaultInterfaceName
	}

	return Bootstrap{
		ControlPlaneURL: cpURL,
		Username:        user,
		Password:        pass,
		InterfaceName:   iface,
	}, nil
}
