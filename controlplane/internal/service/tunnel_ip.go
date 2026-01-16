// tunnel_ip.go manages WireGuard tunnel IP allocation for the Zero Trust network.
//
// Each Enforcer has its own tunnel subnet (e.g., 10.0.0.0/24), and clients connecting
// to that enforcer are assigned unique IPs from this subnet:
//   - .1 is reserved for the enforcer itself
//   - .2-.254 are assigned to clients
//
// The allocator ensures:
//   - Idempotency: the same client always receives the same IP
//   - Uniqueness: different clients never receive the same IP
//   - Thread-safety: concurrent requests are safely handled
//
// Note: This is an in-memory allocator. IP assignments are lost on restart.
// For production, consider persisting allocations to the database.
package service

import (
	"errors"
	"net"
	"sync"
)

var (
	tunnelIPMu    sync.Mutex
	tunnelIPAlloc = make(map[string]map[string]string) // enforcerID -> clientID -> tunnelIP
)

// getAllocatedTunnelIP returns the tunnel IP previously allocated to a client.
// Returns empty string if the client has no allocation yet.
// Used by GetEnforcerConfig to include client IPs in WireGuard peer configuration.
func getAllocatedTunnelIP(enforcerID, clientID string) string {
	tunnelIPMu.Lock()
	defer tunnelIPMu.Unlock()
	if m := tunnelIPAlloc[enforcerID]; m != nil {
		return m[clientID]
	}
	return ""
}

// allocateTunnelIP assigns a tunnel IP to a client within an enforcer's subnet.
// If the client already has an allocation, returns the existing IP (idempotent).
// Otherwise, finds the next available IP starting from .2.
// Used by GetClientConfig when a client requests its configuration.
func allocateTunnelIP(enforcerID, clientID, subnet string) (string, error) {
	tunnelIPMu.Lock()
	defer tunnelIPMu.Unlock()

	if tunnelIPAlloc[enforcerID] == nil {
		tunnelIPAlloc[enforcerID] = make(map[string]string)
	}

	// Idempotent: return existing allocation if present
	if ip, ok := tunnelIPAlloc[enforcerID][clientID]; ok {
		return ip, nil
	}

	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", errors.New("only IPv4 supported")
	}

	// Build set of already-used IPs
	usedIPs := make(map[string]bool)
	for _, allocated := range tunnelIPAlloc[enforcerID] {
		usedIPs[allocated] = true
	}

	// Find first available IP (.1 is enforcer, start from .2)
	ip[3] = 2
	for ip[3] < 255 {
		candidate := ip.String()
		if !usedIPs[candidate] && ipNet.Contains(ip) {
			tunnelIPAlloc[enforcerID][clientID] = candidate
			return candidate, nil
		}
		ip[3]++
	}

	return "", errors.New("no available IP in subnet")
}
