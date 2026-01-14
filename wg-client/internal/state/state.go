package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"migration-to-zero-trust/wg-client/internal/controlplane"
)

const DefaultDir = "/var/lib/migration-to-zero-trust"

func PathForInterface(ifaceName string) string {
	if ifaceName == "" {
		ifaceName = "wg0"
	}
	return filepath.Join(DefaultDir, ifaceName+".state.json")
}

type State struct {
	ControlPlaneURL string                    `json:"control_plane_url"`
	InterfaceName   string                    `json:"interface_name"`
	Config          controlplane.ClientConfig `json:"config"`
	UpdatedAt       time.Time                 `json:"updated_at"`
}

func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}
	return st, nil
}

func Save(path string, st State) error {
	if st.UpdatedAt.IsZero() {
		st.UpdatedAt = time.Now().UTC()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ensure state dir: %w", err)
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "client.state.*.json")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replace state: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod state: %w", err)
	}
	return nil
}
