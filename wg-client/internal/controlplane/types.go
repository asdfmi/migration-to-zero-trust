package controlplane

import "time"

type Session struct {
	ClientID  string
	Token     string
	ExpiresAt time.Time
}

type ClientConfig struct {
	ClientID         string   `json:"client_id"`
	WGPublicKey      string   `json:"wg_public_key"`
	Address          string   `json:"address"`
	GatewayPublicKey string   `json:"gateway_public_key"`
	GatewayEndpoint  string   `json:"gateway_endpoint"`
	AllowedCIDRs     []string `json:"allowed_cidrs"`
}
