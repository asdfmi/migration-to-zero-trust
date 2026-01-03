package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

type Config struct {
	WG WGConfig `yaml:"wg"`
}

type WGConfig struct {
	Iface          string   `yaml:"iface"`
	ListenPort     int      `yaml:"listen_port"`
	PrivateKey     string   `yaml:"private_key"`
	Address        string   `yaml:"address"`
	ServerEndpoint string   `yaml:"server_endpoint"`
	ServerKey      string   `yaml:"server_public_key"`
	AllowedIPs     []string `yaml:"allowed_ips"`
	KeepaliveSec   *int     `yaml:"persistent_keepalive_sec"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []string

	iface := strings.TrimSpace(c.WG.Iface)
	if iface == "" {
		errs = append(errs, "wg.iface is required")
	}
	if c.WG.ListenPort < 0 || c.WG.ListenPort > 65535 {
		errs = append(errs, "wg.listen_port must be 0-65535")
	}
	if strings.TrimSpace(c.WG.PrivateKey) == "" {
		errs = append(errs, "wg.private_key is required")
	} else if _, err := wgtypes.ParseKey(c.WG.PrivateKey); err != nil {
		errs = append(errs, "wg.private_key is invalid")
	}
	if strings.TrimSpace(c.WG.Address) == "" {
		errs = append(errs, "wg.address is required")
	} else if _, _, err := net.ParseCIDR(c.WG.Address); err != nil {
		errs = append(errs, "wg.address must be CIDR")
	}
	if strings.TrimSpace(c.WG.ServerEndpoint) == "" {
		errs = append(errs, "wg.server_endpoint is required")
	} else if _, _, err := net.SplitHostPort(c.WG.ServerEndpoint); err != nil {
		errs = append(errs, "wg.server_endpoint must be host:port")
	}
	if strings.TrimSpace(c.WG.ServerKey) == "" {
		errs = append(errs, "wg.server_public_key is required")
	} else if _, err := wgtypes.ParseKey(c.WG.ServerKey); err != nil {
		errs = append(errs, "wg.server_public_key is invalid")
	}
	if len(c.WG.AllowedIPs) == 0 {
		errs = append(errs, "wg.allowed_ips must not be empty")
	}
	for i, cidr := range c.WG.AllowedIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, fmt.Sprintf("wg.allowed_ips[%d] must be CIDR", i))
		}
	}
	if c.WG.KeepaliveSec != nil && *c.WG.KeepaliveSec < 0 {
		errs = append(errs, "wg.persistent_keepalive_sec must be >= 0")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
