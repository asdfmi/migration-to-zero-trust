package model

import (
	"crypto/sha256"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Gateway struct {
	ID           string `gorm:"primaryKey" json:"id"`
	Name         string `gorm:"uniqueIndex;not null" json:"name"`
	APIKey       string `gorm:"-" json:"api_key,omitempty"`
	APIKeyHash   string `gorm:"column:api_key_hash;not null" json:"-"`
	WGPublicKey  string `gorm:"column:wg_public_key" json:"wg_public_key"`
	Endpoint     string `gorm:"not null" json:"endpoint"`
	TunnelSubnet string `gorm:"column:tunnel_subnet;not null" json:"tunnel_subnet"`
}

func NewGateway(name, endpoint, tunnelSubnet string) (Gateway, error) {
	id := uuid.NewString()
	secret := uuid.NewString()
	apiKey := "gw_" + id + "_" + secret

	// SHA-256 first to handle keys longer than bcrypt's 72-byte limit
	h := sha256.Sum256([]byte(apiKey))
	hash, err := bcrypt.GenerateFromPassword(h[:], bcrypt.DefaultCost)
	if err != nil {
		return Gateway{}, err
	}

	return Gateway{
		ID:           id,
		Name:         name,
		APIKey:       apiKey,
		APIKeyHash:   string(hash),
		Endpoint:     endpoint,
		TunnelSubnet: tunnelSubnet,
	}, nil
}

func (g Gateway) VerifyAPIKey(apiKey string) bool {
	h := sha256.Sum256([]byte(apiKey))
	return bcrypt.CompareHashAndPassword([]byte(g.APIKeyHash), h[:]) == nil
}

func (g Gateway) TunnelAddress() (string, error) {
	_, ipNet, err := net.ParseCIDR(g.TunnelSubnet)
	if err != nil {
		return "", err
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", errors.New("only IPv4 supported")
	}
	ip[3] = 1
	ones, _ := ipNet.Mask.Size()
	return ip.String() + "/" + strconv.Itoa(ones), nil
}

// ParseAPIKey extracts gateway ID from API key format "gw_<id>_<secret>"
func ParseAPIKey(apiKey string) (gatewayID string, ok bool) {
	parts := strings.SplitN(apiKey, "_", 3)
	if len(parts) != 3 || parts[0] != "gw" {
		return "", false
	}
	return parts[1], true
}
