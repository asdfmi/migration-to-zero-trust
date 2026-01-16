// client_config.go generates WireGuard configuration for clients.
//
// When a client authenticates and requests its configuration, this service:
//  1. Groups the client's resource pairs by gateway
//  2. Allocates a tunnel IP for each gateway
//  3. Determines which resource CIDRs the client can access per gateway
//  4. Returns configurations for all gateways the client needs to connect to
//
// Access Control Logic (observe/enforce modes):
//   - observe mode: All authenticated clients can access these resources.
//     Used during migration to monitor traffic before enforcing policies.
//   - enforce mode: Only clients explicitly paired with the resource can access it.
//     Used after migration when Zero Trust policies are fully enforced.
//
// The returned config is used by the client agent to configure WireGuard peers.
package service

import (
	"context"
	"net"
	"sort"
	"strconv"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

// ClientConfig contains everything a client needs to establish WireGuard tunnels
// to one or more gateways.
type ClientConfig struct {
	ClientID    string                `json:"client_id"`
	WGPublicKey string                `json:"wg_public_key"`
	Gateways    []ClientGatewayConfig `json:"gateways"`
}

// ClientGatewayConfig contains the configuration for connecting to a single gateway.
type ClientGatewayConfig struct {
	GatewayID        string   `json:"gateway_id"`
	TunnelIP         string   `json:"tunnel_ip"`          // Client's IP in this gateway's tunnel (e.g., "10.0.0.2/24")
	GatewayPublicKey string   `json:"gateway_public_key"` // Gateway's WireGuard public key
	GatewayEndpoint  string   `json:"gateway_endpoint"`   // Gateway's public endpoint (e.g., "gw.example.com:51820")
	AllowedCIDRs     []string `json:"allowed_cidrs"`      // Resource CIDRs to route through this gateway
}

// GetClientConfig generates the WireGuard configuration for an authenticated client.
// Returns configurations for all gateways the client has access to.
func GetClientConfig(ctx context.Context, repo repository.Repository, claims ClientClaims) (ClientConfig, error) {
	data, err := repo.FetchClientConfigData(ctx, claims.ClientID)
	if err != nil {
		return ClientConfig{}, err
	}
	if len(data.Gateways) == 0 {
		return ClientConfig{}, ValidationError{Msg: "no resources available for client"}
	}

	// Group pairs by gateway
	gatewayPairs := make(map[string][]model.Pair)
	for _, p := range data.Pairs {
		gatewayPairs[p.Resource.GatewayID] = append(gatewayPairs[p.Resource.GatewayID], p)
	}

	// Build gateway configs for all gateways (both paired and observe-only)
	var gateways []ClientGatewayConfig
	for gatewayID, gateway := range data.Gateways {
		// Allocate or retrieve existing tunnel IP for this client on this gateway
		tunnelIP, err := allocateTunnelIP(gatewayID, data.Client.ID, gateway.TunnelSubnet)
		if err != nil {
			return ClientConfig{}, err
		}

		// Get prefix length for the tunnel IP
		_, ipNet, err := net.ParseCIDR(gateway.TunnelSubnet)
		if err != nil {
			return ClientConfig{}, err
		}
		ones, _ := ipNet.Mask.Size()

		// Build the list of CIDRs this client can access via this gateway:
		//   - All observe mode resources on this gateway
		//   - All enforce mode resources that are explicitly paired with this client
		cidrSet := make(map[string]struct{})

		// Add observe resources for this gateway
		for _, r := range data.GatewayResources[gatewayID] {
			if r.Mode == model.ModeObserve {
				cidrSet[r.CIDR] = struct{}{}
			}
		}

		// Add paired resources (enforce mode)
		for _, p := range gatewayPairs[gatewayID] {
			cidrSet[p.Resource.CIDR] = struct{}{}
		}

		cidrs := make([]string, 0, len(cidrSet))
		for cidr := range cidrSet {
			cidrs = append(cidrs, cidr)
		}
		sort.Strings(cidrs)

		gateways = append(gateways, ClientGatewayConfig{
			GatewayID:        gatewayID,
			TunnelIP:         tunnelIP + "/" + strconv.Itoa(ones),
			GatewayPublicKey: gateway.WGPublicKey,
			GatewayEndpoint:  gateway.Endpoint,
			AllowedCIDRs:     cidrs,
		})
	}

	// Sort gateways for deterministic output
	sort.Slice(gateways, func(i, j int) bool {
		return gateways[i].GatewayID < gateways[j].GatewayID
	})

	return ClientConfig{
		ClientID:    data.Client.ID,
		WGPublicKey: data.Client.WGPublicKey,
		Gateways:    gateways,
	}, nil
}
