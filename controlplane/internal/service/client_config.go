// client_config.go generates WireGuard configuration for clients.
//
// When a client authenticates and requests its configuration, this service:
//  1. Groups the client's resource pairs by enforcer
//  2. Allocates a tunnel IP for each enforcer
//  3. Determines which resource CIDRs the client can access per enforcer
//  4. Returns configurations for all enforcers the client needs to connect to
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
// to one or more enforcers.
type ClientConfig struct {
	ClientID    string                 `json:"client_id"`
	WGPublicKey string                 `json:"wg_public_key"`
	Enforcers   []ClientEnforcerConfig `json:"enforcers"`
}

// ClientEnforcerConfig contains the configuration for connecting to a single enforcer.
type ClientEnforcerConfig struct {
	EnforcerID        string   `json:"enforcer_id"`
	TunnelIP          string   `json:"tunnel_ip"`           // Client's IP in this enforcer's tunnel (e.g., "10.0.0.2/24")
	EnforcerPublicKey string   `json:"enforcer_public_key"` // Enforcer's WireGuard public key
	EnforcerEndpoint  string   `json:"enforcer_endpoint"`   // Enforcer's public endpoint (e.g., "enf.example.com:51820")
	AllowedCIDRs      []string `json:"allowed_cidrs"`       // Resource CIDRs to route through this enforcer
}

// GetClientConfig generates the WireGuard configuration for an authenticated client.
// Returns configurations for all enforcers the client has access to.
func GetClientConfig(ctx context.Context, repo repository.Repository, claims ClientClaims) (ClientConfig, error) {
	data, err := repo.FetchClientConfigData(ctx, claims.ClientID)
	if err != nil {
		return ClientConfig{}, err
	}
	if len(data.Enforcers) == 0 {
		return ClientConfig{}, ValidationError{Msg: "no resources available for client"}
	}

	// Group pairs by enforcer
	enforcerPairs := make(map[string][]model.Pair)
	for _, p := range data.Pairs {
		enforcerPairs[p.Resource.EnforcerID] = append(enforcerPairs[p.Resource.EnforcerID], p)
	}

	// Build enforcer configs for all enforcers (both paired and observe-only)
	var enforcers []ClientEnforcerConfig
	for enforcerID, enforcer := range data.Enforcers {
		// Allocate or retrieve existing tunnel IP for this client on this enforcer
		tunnelIP, err := allocateTunnelIP(enforcerID, data.Client.ID, enforcer.TunnelSubnet)
		if err != nil {
			return ClientConfig{}, err
		}

		// Get prefix length for the tunnel IP
		_, ipNet, err := net.ParseCIDR(enforcer.TunnelSubnet)
		if err != nil {
			return ClientConfig{}, err
		}
		ones, _ := ipNet.Mask.Size()

		// Build the list of CIDRs this client can access via this enforcer:
		//   - All observe mode resources on this enforcer
		//   - All enforce mode resources that are explicitly paired with this client
		cidrSet := make(map[string]struct{})

		// Add observe resources for this enforcer
		for _, r := range data.EnforcerResources[enforcerID] {
			if r.Mode == model.ModeObserve {
				cidrSet[r.CIDR] = struct{}{}
			}
		}

		// Add paired resources (enforce mode)
		for _, p := range enforcerPairs[enforcerID] {
			cidrSet[p.Resource.CIDR] = struct{}{}
		}

		cidrs := make([]string, 0, len(cidrSet))
		for cidr := range cidrSet {
			cidrs = append(cidrs, cidr)
		}
		sort.Strings(cidrs)

		enforcers = append(enforcers, ClientEnforcerConfig{
			EnforcerID:        enforcerID,
			TunnelIP:          tunnelIP + "/" + strconv.Itoa(ones),
			EnforcerPublicKey: enforcer.WGPublicKey,
			EnforcerEndpoint:  enforcer.Endpoint,
			AllowedCIDRs:      cidrs,
		})
	}

	// Sort enforcers for deterministic output
	sort.Slice(enforcers, func(i, j int) bool {
		return enforcers[i].EnforcerID < enforcers[j].EnforcerID
	})

	return ClientConfig{
		ClientID:    data.Client.ID,
		WGPublicKey: data.Client.WGPublicKey,
		Enforcers:   enforcers,
	}, nil
}
