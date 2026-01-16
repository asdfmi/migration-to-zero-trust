package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultWGInterface  = "wg0"
	DefaultWGListenPort = 51820
	DefaultKeyDir       = "/var/lib/enforcer"
	maxPort             = 65535
)

type Env struct {
	ControlPlaneURL string
	APIKey          string

	WGInterface  string
	WGListenPort int
}

func LoadEnv() (Env, error) {
	env := Env{
		ControlPlaneURL: os.Getenv("CONTROLPLANE_URL"),
		APIKey:          os.Getenv("API_KEY"),
		WGInterface:     os.Getenv("WG_INTERFACE"),
	}

	if port := os.Getenv("WG_LISTEN_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return Env{}, fmt.Errorf("WG_LISTEN_PORT: %w", err)
		}
		env.WGListenPort = p
	} else {
		env.WGListenPort = DefaultWGListenPort
	}

	if env.WGInterface == "" {
		env.WGInterface = DefaultWGInterface
	}

	var errs []string
	if strings.TrimSpace(env.ControlPlaneURL) == "" {
		errs = append(errs, "CONTROLPLANE_URL is required")
	}
	if strings.TrimSpace(env.APIKey) == "" {
		errs = append(errs, "API_KEY is required")
	}
	if env.WGListenPort <= 0 || env.WGListenPort > maxPort {
		errs = append(errs, "WG_LISTEN_PORT must be 1-65535")
	}
	if len(errs) > 0 {
		return Env{}, errors.New(strings.Join(errs, "; "))
	}

	return env, nil
}
