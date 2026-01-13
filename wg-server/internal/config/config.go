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

const (
	AuthzModeObserve = "observe"
	AuthzModeEnforce = "enforce"
)

type Config struct {
	WG      WGConfig      `yaml:"wg"`
	Authz   AuthzConfig   `yaml:"authz"`
	Logging LoggingConfig `yaml:"logging"`
	Policy  PolicyConfig  `yaml:"policy"`
}

type WGConfig struct {
	Iface      string       `yaml:"iface"`
	ListenPort int          `yaml:"listen_port"`
	PrivateKey string       `yaml:"private_key"`
	Address    string       `yaml:"address"`
	Peers      []PeerConfig `yaml:"peers"`
}

type PeerConfig struct {
	PublicKey  string   `yaml:"public_key"`
	AllowedIPs []string `yaml:"allowed_ips"`
}

type AuthzConfig struct {
	Mode string `yaml:"mode"`
}

type LoggingConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Group   int    `yaml:"group"`
}

type PolicyConfig struct {
	Rules []PolicyRule `yaml:"rules"`
}

type PolicyRule struct {
	ClientID     string   `yaml:"client_id"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
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

	if cfg.Authz.Mode == "" {
		cfg.Authz.Mode = AuthzModeObserve
	}
	if cfg.Logging.Path == "" {
		cfg.Logging.Path = "/var/log/wg-server/events.jsonl"
	}
	if cfg.Logging.Group == 0 {
		cfg.Logging.Group = 100
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []string

	iface := strings.TrimSpace(c.WG.Iface)
	if iface == "" {
		errs = append(errs, "wg.iface is required")
	}
	if c.WG.ListenPort <= 0 || c.WG.ListenPort > 65535 {
		errs = append(errs, "wg.listen_port must be 1-65535")
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
	if len(c.WG.Peers) == 0 {
		errs = append(errs, "wg.peers must not be empty")
	}
	for i, peer := range c.WG.Peers {
		if strings.TrimSpace(peer.PublicKey) == "" {
			errs = append(errs, fmt.Sprintf("wg.peers[%d].public_key is required", i))
		} else if _, err := wgtypes.ParseKey(peer.PublicKey); err != nil {
			errs = append(errs, fmt.Sprintf("wg.peers[%d].public_key is invalid", i))
		}
		if len(peer.AllowedIPs) == 0 {
			errs = append(errs, fmt.Sprintf("wg.peers[%d].allowed_ips must not be empty", i))
		}
		for j, cidr := range peer.AllowedIPs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				errs = append(errs, fmt.Sprintf("wg.peers[%d].allowed_ips[%d] must be CIDR", i, j))
			}
		}
	}

	switch c.Authz.Mode {
	case AuthzModeObserve, AuthzModeEnforce:
		// ok
	default:
		errs = append(errs, "authz.mode must be observe or enforce")
	}
	if c.Authz.Mode == AuthzModeEnforce {
		if len(c.Policy.Rules) == 0 {
			errs = append(errs, "policy.rules must not be empty when authz.mode is enforce")
		}
	}
	if c.Logging.Group < 0 || c.Logging.Group > 65535 {
		errs = append(errs, "logging.group must be 0-65535")
	}
	if strings.TrimSpace(c.Logging.Path) == "" {
		errs = append(errs, "logging.path must not be empty")
	}

	peerKeys := make(map[string]struct{}, len(c.WG.Peers))
	for _, peer := range c.WG.Peers {
		peerKeys[peer.PublicKey] = struct{}{}
	}

	for i, rule := range c.Policy.Rules {
		if strings.TrimSpace(rule.ClientID) == "" {
			errs = append(errs, fmt.Sprintf("policy.rules[%d].client_id is required", i))
		} else if _, ok := peerKeys[rule.ClientID]; !ok {
			errs = append(errs, fmt.Sprintf("policy.rules[%d].client_id must match wg.peers public_key", i))
		}
		if len(rule.AllowedCIDRs) == 0 {
			errs = append(errs, fmt.Sprintf("policy.rules[%d].allowed_cidrs must not be empty", i))
		}
		for j, cidr := range rule.AllowedCIDRs {
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				errs = append(errs, fmt.Sprintf("policy.rules[%d].allowed_cidrs[%d] must be CIDR", i, j))
				continue
			}
			if ip.To4() == nil || ipNet == nil || ipNet.IP.To4() == nil {
				errs = append(errs, fmt.Sprintf("policy.rules[%d].allowed_cidrs[%d] must be IPv4 CIDR", i, j))
			}
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
