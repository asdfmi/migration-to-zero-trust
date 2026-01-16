package wireguard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	DefaultKeyDir  = "/var/lib/enforcer"
	PrivateKeyFile = "private.key"
)

type KeyPair struct {
	PrivateKey wgtypes.Key
	PublicKey  wgtypes.Key
}

func LoadOrGenerateKeyPair(keyDir string) (*KeyPair, error) {
	if keyDir == "" {
		keyDir = DefaultKeyDir
	}

	keyPath := filepath.Join(keyDir, PrivateKeyFile)

	// Try to load existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		privKeyStr := strings.TrimSpace(string(data))
		privKey, err := wgtypes.ParseKey(privKeyStr)
		if err != nil {
			return nil, errors.New("invalid private key in file")
		}
		return &KeyPair{
			PrivateKey: privKey,
			PublicKey:  privKey.PublicKey(),
		}, nil
	}

	// Generate new key pair
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	// Ensure directory exists
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, err
	}

	// Save private key
	if err := os.WriteFile(keyPath, []byte(privKey.String()+"\n"), 0600); err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privKey,
		PublicKey:  privKey.PublicKey(),
	}, nil
}
