package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	pathLogin  = "/api/client/login"
	pathConfig = "/api/client/config"
)

var ErrUnauthorized = errors.New("unauthorized")

type Client struct {
	resty *resty.Client
}

type Session struct {
	Token string
}

// ClientConfig contains configurations for all gateways the client needs to connect to.
type ClientConfig struct {
	ClientID    string                `json:"client_id"`
	WGPublicKey string                `json:"wg_public_key"`
	Gateways    []ClientGatewayConfig `json:"gateways"`
}

// ClientGatewayConfig contains the configuration for connecting to a single gateway.
type ClientGatewayConfig struct {
	GatewayID        string   `json:"gateway_id"`
	TunnelIP         string   `json:"tunnel_ip"`
	GatewayPublicKey string   `json:"gateway_public_key"`
	GatewayEndpoint  string   `json:"gateway_endpoint"`
	AllowedCIDRs     []string `json:"allowed_cidrs"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

func New(baseURL string) *Client {
	client := resty.New().
		SetBaseURL(strings.TrimRight(baseURL, "/")).
		SetTimeout(10 * time.Second)
	return &Client{resty: client}
}

func (c *Client) Login(ctx context.Context, username, password string) (Session, error) {
	var result loginResponse
	resp, err := c.resty.R().
		SetContext(ctx).
		SetBody(&loginRequest{Username: username, Password: password}).
		SetResult(&result).
		Post(pathLogin)
	if err != nil {
		return Session{}, err
	}
	if resp.StatusCode() == http.StatusUnauthorized {
		return Session{}, ErrUnauthorized
	}
	if resp.IsError() {
		return Session{}, errors.New(resp.String())
	}
	return Session{Token: result.Token}, nil
}

func (c *Client) FetchConfig(ctx context.Context, token string) (ClientConfig, error) {
	var cfg ClientConfig
	resp, err := c.resty.R().
		SetContext(ctx).
		SetAuthToken(token).
		SetResult(&cfg).
		Get(pathConfig)
	if err != nil {
		return ClientConfig{}, err
	}
	if resp.StatusCode() == http.StatusUnauthorized {
		return ClientConfig{}, ErrUnauthorized
	}
	if resp.IsError() {
		return ClientConfig{}, errors.New(resp.String())
	}
	return cfg, nil
}
