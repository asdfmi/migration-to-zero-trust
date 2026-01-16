package routing

import (
	"net"
	"sort"

	"github.com/vishvananda/netlink"
)

// RouteInfo represents routing information for a specific CIDR
type RouteInfo struct {
	Interface string
	CIDR      string
	Priority  int // lower is higher priority (more specific prefix)
}

// ResourceRouting represents routing status for a resource
type ResourceRouting struct {
	ResourceCIDR string
	Routes       []RouteInfo
	Preferred    string // interface name that will be used
	HasConflict  bool   // true if multiple routes exist
}

// ResolvePreferredInterface determines which interface will be used for each CIDR
// and detects routing conflicts (e.g., VPN vs WireGuard).
func ResolvePreferredInterface(allowedCIDRs []string) ([]ResourceRouting, error) {
	// Get all routes
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	// Build interface name map
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	ifaceNames := make(map[int]string)
	for _, link := range links {
		ifaceNames[link.Attrs().Index] = link.Attrs().Name
	}

	var results []ResourceRouting

	for _, cidr := range allowedCIDRs {
		_, targetNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		targetIP := targetNet.IP

		rr := ResourceRouting{
			ResourceCIDR: cidr,
		}

		// Find all routes that cover this CIDR
		for _, route := range routes {
			if route.Dst == nil {
				// Default route (0.0.0.0/0)
				continue
			}

			if route.Dst.Contains(targetIP) {
				ifaceName := ifaceNames[route.LinkIndex]
				ones, _ := route.Dst.Mask.Size()
				rr.Routes = append(rr.Routes, RouteInfo{
					Interface: ifaceName,
					CIDR:      route.Dst.String(),
					Priority:  -ones, // negative so higher prefix = lower value = higher priority
				})
			}
		}

		// Sort by priority (most specific first)
		sort.Slice(rr.Routes, func(i, j int) bool {
			return rr.Routes[i].Priority < rr.Routes[j].Priority
		})

		// Determine preferred route
		if len(rr.Routes) > 0 {
			rr.Preferred = rr.Routes[0].Interface
			rr.HasConflict = len(rr.Routes) > 1
		}

		results = append(results, rr)
	}

	return results, nil
}
