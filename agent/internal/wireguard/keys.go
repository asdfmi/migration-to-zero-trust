package wireguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LoadOrGenerateKeyPair loads an existing private key from path or generates a new one.
// Returns (privateKey, publicKey, error).
func LoadOrGenerateKeyPair(path string) (wgtypes.Key, wgtypes.Key, error) {
	// Try to load existing key
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
		if err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("parse private key: %w", err)
		}
		return key, key.PublicKey(), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}

	// Generate new key
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("generate key: %w", err)
	}

	// Save to file
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(path, []byte(key.String()), 0o600); err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("write key: %w", err)
	}

	return key, key.PublicKey(), nil
}
