package wireguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func EnsureKeyPair(path string) (wgtypes.Key, wgtypes.Key, error) {
	key, err := loadPrivateKey(path)
	if err == nil {
		return key, key.PublicKey(), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}

	key, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, fmt.Errorf("generate key: %w", err)
	}
	if err := writePrivateKey(path, key); err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}
	return key, key.PublicKey(), nil
}

func loadPrivateKey(path string) (wgtypes.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	key, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

func writePrivateKey(path string, key wgtypes.Key) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(path, []byte(key.String()), 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
