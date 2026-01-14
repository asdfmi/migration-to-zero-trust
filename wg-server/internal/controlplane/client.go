package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
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
	CIDR string `json:"cidr"`
	Mode string `json:"mode"`
}

func (c *Client) FetchConfig(ctx context.Context) (*GatewayConfig, error) {
	url := fmt.Sprintf("%s/api/gateway/config", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var cfg GatewayConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &cfg, nil
}

type LogEntry struct {
	Timestamp  time.Time `json:"ts"`
	SrcIP      string    `json:"src_ip,omitempty"`
	SrcPort    int       `json:"src_port,omitempty"`
	DstIP      string    `json:"dst_ip,omitempty"`
	DstPort    int       `json:"dst_port,omitempty"`
	Proto      string    `json:"proto,omitempty"`
	ClientID   string    `json:"client_id,omitempty"`
	ClientName string    `json:"client_name,omitempty"`
	Length     int       `json:"length"`
}

func (c *Client) PushLogs(ctx context.Context, entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	url := fmt.Sprintf("%s/api/logs", c.baseURL)

	body, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal logs: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

type UpdatePublicKeyRequest struct {
	WGPublicKey string `json:"wg_public_key"`
}

func (c *Client) UpdatePublicKey(ctx context.Context, wgPublicKey string) error {
	url := fmt.Sprintf("%s/api/gateway/public-key", c.baseURL)

	reqBody := UpdatePublicKeyRequest{
		WGPublicKey: wgPublicKey,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
