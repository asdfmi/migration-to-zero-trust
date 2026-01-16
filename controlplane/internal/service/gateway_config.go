// gateway_config.go generates policy configuration for gateways.
//
// Gateways periodically poll this configuration to update their:
//  1. WireGuard peer list (which clients can connect)
//  2. Access control policies (which clients can access which resources)
//
// The gateway uses this config to:
//   - Configure WireGuard peers with client public keys and allowed IPs
//   - Enforce or observe traffic based on resource mode
//
// Policy Building Logic:
//   - Each client with at least one pair gets a Policy entry
//   - observe mode resources: added to ALL clients' allowed CIDRs
//   - enforce mode resources: added only to paired clients' allowed CIDRs
//
// This enables gradual Zero Trust migration:
//   - Start with "observe" to monitor traffic without blocking
//   - Switch to "enforce" when ready to apply strict access control
package service

import (
	"context"
	"sort"

	"migration-to-zero-trust/controlplane/internal/model"
	"migration-to-zero-trust/controlplane/internal/repository"
)

// Policy defines access control for a single client on a gateway.
type Policy struct {
	ClientID     string         `json:"client_id"`
	ClientName   string         `json:"client_name"`
	WGPublicKey  string         `json:"wg_public_key"` // For WireGuard peer configuration
	AllowedIPs   []string       `json:"allowed_ips"`   // Client's tunnel IPs (for WireGuard AllowedIPs)
	AllowedCIDRs []PolicyTarget `json:"allowed_cidrs"` // Resources this client can access
}

// PolicyTarget represents a resource CIDR with its access mode.
type PolicyTarget struct {
	CIDR         string `json:"cidr"`
	Mode         string `json:"mode"` // "observe" (log only) or "enforce" (block unauthorized)
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
}

// GatewayConfig is the complete configuration a gateway needs to operate.
type GatewayConfig struct {
	GatewayID     string   `json:"gateway_id"`
	TunnelAddress string   `json:"tunnel_address"` // Gateway's tunnel IP (e.g., "10.0.0.1/24")
	Policies      []Policy `json:"policies"`       // Per-client access policies
}

// GetGatewayConfig generates the complete configuration for a gateway.
// Called by gateways polling for configuration updates.
func GetGatewayConfig(ctx context.Context, repo repository.Repository, id string) (GatewayConfig, error) {
	data, err := repo.FetchGatewayConfigData(ctx, id)
	if err != nil {
		return GatewayConfig{}, err
	}

	tunnelAddr, err := data.Gateway.TunnelAddress()
	if err != nil {
		return GatewayConfig{}, err
	}

	// Categorize resources by mode:
	//   - observe: will be added to ALL clients
	//   - enforce: will be added only to paired clients
	var observeResources []model.Resource
	enforceResourceIDs := make(map[string]model.Resource)
	for _, r := range data.Resources {
		if r.Mode == model.ModeObserve {
			observeResources = append(observeResources, r)
		} else {
			enforceResourceIDs[r.ID] = r
		}
	}

	// Build policies for all clients
	policyMap := make(map[string]*Policy)

	// If there are observe resources, create policies for ALL clients
	for _, c := range data.Clients {
		entry := &Policy{
			ClientID:    c.ID,
			ClientName:  c.Name,
			WGPublicKey: c.WGPublicKey,
		}
		// Add all observe resources
		for _, r := range observeResources {
			entry.AllowedCIDRs = append(entry.AllowedCIDRs, PolicyTarget{
				CIDR:         r.CIDR,
				Mode:         r.Mode,
				ResourceID:   r.ID,
				ResourceName: r.Name,
			})
		}
		policyMap[c.ID] = entry
	}

	// Add enforce resources for paired clients
	for _, p := range data.Pairs {
		entry := policyMap[p.ClientID]
		if entry == nil {
			// Client not in Clients list (no observe resources) - create new policy
			entry = &Policy{
				ClientID:    p.ClientID,
				ClientName:  p.Client.Name,
				WGPublicKey: p.Client.WGPublicKey,
			}
			policyMap[p.ClientID] = entry
		}

		// Add enforce resource only if this specific pair grants access
		if res, isEnforce := enforceResourceIDs[p.ResourceID]; isEnforce {
			entry.AllowedCIDRs = append(entry.AllowedCIDRs, PolicyTarget{
				CIDR:         res.CIDR,
				Mode:         res.Mode,
				ResourceID:   res.ID,
				ResourceName: res.Name,
			})
		}
	}

	// Convert map to sorted slice for deterministic output
	policies := make([]Policy, 0, len(policyMap))
	for _, entry := range policyMap {
		// Include client's tunnel IP for WireGuard AllowedIPs
		if tunnelIP := getAllocatedTunnelIP(data.Gateway.ID, entry.ClientID); tunnelIP != "" {
			entry.AllowedIPs = []string{tunnelIP + "/32"}
		}
		sort.Slice(entry.AllowedCIDRs, func(i, j int) bool {
			return entry.AllowedCIDRs[i].CIDR < entry.AllowedCIDRs[j].CIDR
		})
		policies = append(policies, *entry)
	}
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].ClientID < policies[j].ClientID
	})

	return GatewayConfig{
		GatewayID:     id,
		TunnelAddress: tunnelAddr,
		Policies:      policies,
	}, nil
}
