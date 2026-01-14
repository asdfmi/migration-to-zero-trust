package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Login(ctx context.Context, username, password string) (Session, error) {
	body := map[string]string{
		"username": username,
		"password": password,
	}
	var resp struct {
		ClientID  string `json:"client_id"`
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := c.postJSON(ctx, "/api/client/login", body, &resp, ""); err != nil {
		return Session{}, err
	}
	exp, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse expires_at: %w", err)
	}
	return Session{
		ClientID:  resp.ClientID,
		Token:     resp.Token,
		ExpiresAt: exp,
	}, nil
}

func (c *Client) FetchConfig(ctx context.Context, token string) (ClientConfig, error) {
	var cfg ClientConfig
	if err := c.getJSON(ctx, "/api/client/config", &cfg, token); err != nil {
		return ClientConfig{}, err
	}
	return cfg, nil
}

func (c *Client) UpdatePublicKey(ctx context.Context, token, publicKey string) error {
	body := map[string]string{
		"wg_public_key": publicKey,
	}
	return c.putJSON(ctx, "/api/client/keys", body, token)
}

func (c *Client) getJSON(ctx context.Context, path string, dst any, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.do(req, dst)
}

func (c *Client) postJSON(ctx context.Context, path string, body any, dst any, token string) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.do(req, dst)
}

func (c *Client) putJSON(ctx context.Context, path string, body any, token string) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, dst any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		io.Copy(io.Discard, resp.Body)
		return ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("control plane %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if dst == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	dec := json.NewDecoder(resp.Body)
	return dec.Decode(dst)
}
