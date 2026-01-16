package connection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"migration-to-zero-trust/agent/internal/config"
	"migration-to-zero-trust/agent/internal/controlplane"
)

const DefaultDir = "/var/lib/migration-to-zero-trust"

type State struct {
	ControlPlaneURL string                    `json:"controlplane_url"`
	InterfaceName   string                    `json:"interface_name"`
	Config          controlplane.ClientConfig `json:"config"`
	UpdatedAt       time.Time                 `json:"updated_at"`
}

func PathForInterface(ifaceName string) string {
	if ifaceName == "" {
		ifaceName = config.DefaultInterfaceName
	}
	return filepath.Join(DefaultDir, ifaceName+".connection.json")
}

func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("read connection info: %w", err)
	}
	var info State
	if err := json.Unmarshal(data, &info); err != nil {
		return State{}, fmt.Errorf("decode connection info: %w", err)
	}
	return info, nil
}

func Save(path string, state State) error {
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ensure dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return os.WriteFile(path, data, 0o600)
}
