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
	DefaultKeyDir       = "/var/lib/wg-server"
)

type Env struct {
	ControlPlaneURL string
	APIKey          string

	WGInterface  string
	WGListenPort int
}

func LoadEnv() (Env, error) {
	env := Env{
		ControlPlaneURL: os.Getenv("CONTROL_PLANE_URL"),
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

	return env, nil
}

func (e Env) Validate() error {
	var errs []string

	if strings.TrimSpace(e.ControlPlaneURL) == "" {
		errs = append(errs, "CONTROL_PLANE_URL is required")
	}
	if strings.TrimSpace(e.APIKey) == "" {
		errs = append(errs, "API_KEY is required")
	}

	if e.WGListenPort <= 0 || e.WGListenPort > 65535 {
		errs = append(errs, "WG_LISTEN_PORT must be 1-65535")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
