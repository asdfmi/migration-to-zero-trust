package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	pathConfig    = "/api/gateway/config"
	pathLogs      = "/api/logs"
	pathPublicKey = "/api/gateway/public-key"
)

type Client struct {
	resty *resty.Client
}

type Gateway struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	WGPublicKey  string `json:"wg_public_key"`
	Endpoint     string `json:"endpoint"`
	TunnelSubnet string `json:"tunnel_subnet"`
}

type GatewayConfig struct {
	GatewayID     string   `json:"gateway_id"`
	TunnelAddress string   `json:"tunnel_address"`
	Policies      []Policy `json:"policies"`
}

type Policy struct {
	ClientID     string         `json:"client_id"`
	ClientName   string         `json:"client_name"`
	WGPublicKey  string         `json:"wg_public_key"`
	AllowedIPs   []string       `json:"allowed_ips"`
	AllowedCIDRs []PolicyTarget `json:"allowed_cidrs"`
}

type PolicyTarget struct {
	CIDR         string `json:"cidr"`
	Mode         string `json:"mode"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
}

type LogEntry struct {
	Timestamp    time.Time `json:"ts"`
	SrcIP        string    `json:"src_ip"`
	SrcPort      int       `json:"src_port"`
	DstIP        string    `json:"dst_ip"`
	DstPort      int       `json:"dst_port"`
	Proto        string    `json:"proto"`
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name"`
	ResourceID   string    `json:"resource_id"`
	ResourceName string    `json:"resource_name"`
	Length       int       `json:"length"`
}

type UpdatePublicKeyRequest struct {
	WGPublicKey string `json:"wg_public_key"`
}

func NewClient(baseURL, apiKey string) *Client {
	client := resty.New().
		SetBaseURL(baseURL).
		SetTimeout(30*time.Second).
		SetHeader("X-API-Key", apiKey)
	return &Client{resty: client}
}

func (c *Client) FetchConfig(ctx context.Context) (*GatewayConfig, error) {
	var cfg GatewayConfig
	resp, err := c.resty.R().
		SetContext(ctx).
		SetResult(&cfg).
		Get(pathConfig)
	if err != nil {
		return nil, err
	}
	if resp.IsError() {
		return nil, errors.New(resp.String())
	}
	return &cfg, nil
}

func (c *Client) PushLogs(ctx context.Context, entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	resp, err := c.resty.R().
		SetContext(ctx).
		SetBody(entries).
		Post(pathLogs)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return errors.New(resp.String())
	}
	return nil
}

func (c *Client) UpdatePublicKey(ctx context.Context, wgPublicKey string) error {
	resp, err := c.resty.R().
		SetContext(ctx).
		SetBody(&UpdatePublicKeyRequest{WGPublicKey: wgPublicKey}).
		Put(pathPublicKey)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return errors.New(resp.String())
	}
	return nil
}
