package firewall

import (
	"bytes"
	"fmt"
	"net"

	"migration-to-zero-trust/enforcer/internal/controlplane"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	nftTableName        = "filter"
	nftNatTableName     = "nat"
	nftBaseChainName    = "forward"
	nftPolicyChain      = "wg-authz"
	nftPostroutingChain = "postrouting"
	iifRegister         = 1
	srcAddrRegister     = 2
	dstAddrRegister     = 3
	ipv4SrcAddrOffset   = 12
	ipv4DstAddrOffset   = 16
)

const DefaultLoggingGroup = 100

type Manager struct {
	iface       string
	table       *nftables.Table
	policyChain *nftables.Chain
}

func NewManager(iface string) *Manager {
	return &Manager{
		iface: iface,
	}
}

// Setup creates the nftables infrastructure for WireGuard traffic filtering.
// It creates filter/NAT tables, chains, and jump rules.
func (m *Manager) Setup() error {
	conn := &nftables.Conn{}

	// --- Create filter table ---
	// Look for existing table or create new one
	var table *nftables.Table
	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == nftTableName && t.Family == nftables.TableFamilyINet {
			table = t
			break
		}
	}
	if table == nil {
		table = &nftables.Table{
			Name:   nftTableName,
			Family: nftables.TableFamilyINet,
		}
		conn.AddTable(table)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nftables add table: %w", err)
		}
	}
	m.table = table

	// --- Create forward base chain ---
	// This is the main chain that hooks into the forward path
	var baseChain *nftables.Chain
	chains, err := conn.ListChains()
	if err != nil {
		return fmt.Errorf("nftables list chains: %w", err)
	}
	for _, c := range chains {
		if c.Table.Name == table.Name && c.Table.Family == table.Family && c.Name == nftBaseChainName {
			baseChain = c
			break
		}
	}
	if baseChain == nil {
		policy := nftables.ChainPolicyAccept
		baseChain = &nftables.Chain{
			Name:     nftBaseChainName,
			Table:    table,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
			Type:     nftables.ChainTypeFilter,
			Policy:   &policy,
		}
		conn.AddChain(baseChain)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nftables add forward chain: %w", err)
		}
	}

	// --- Create policy chain ---
	// This chain holds the actual allow/deny rules for WireGuard traffic
	var policyChain *nftables.Chain
	for _, c := range chains {
		if c.Table.Name == table.Name && c.Table.Family == table.Family && c.Name == nftPolicyChain {
			policyChain = c
			break
		}
	}
	if policyChain == nil {
		policyChain = &nftables.Chain{
			Name:  nftPolicyChain,
			Table: table,
		}
		conn.AddChain(policyChain)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nftables add policy chain: %w", err)
		}
	}
	m.policyChain = policyChain

	// --- Add jump rule from forward to policy chain ---
	// Only traffic from WireGuard interface jumps to policy chain
	rules, err := conn.GetRules(table, baseChain)
	if err != nil {
		return fmt.Errorf("nftables get rules: %w", err)
	}
	hasJump := false
	for _, rule := range rules {
		var matchesIface, matchesJump bool
		for _, e := range rule.Exprs {
			switch exp := e.(type) {
			case *expr.Meta:
				if exp.Key == expr.MetaKeyIIFNAME {
					matchesIface = true
				}
			case *expr.Cmp:
				if bytes.Equal(exp.Data, []byte(m.iface+"\x00")) {
					matchesIface = true
				}
			case *expr.Verdict:
				if exp.Kind == expr.VerdictJump && exp.Chain == nftPolicyChain {
					matchesJump = true
				}
			}
		}
		if matchesIface && matchesJump {
			hasJump = true
			break
		}
	}
	if !hasJump {
		conn.InsertRule(&nftables.Rule{
			Table: table,
			Chain: baseChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: iifRegister},
				&expr.Cmp{Op: expr.CmpOpEq, Register: iifRegister, Data: []byte(m.iface + "\x00")},
				&expr.Verdict{Kind: expr.VerdictJump, Chain: nftPolicyChain},
			},
		})
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nftables insert jump rule: %w", err)
		}
	}

	// --- Create NAT table ---
	// For masquerading WireGuard traffic to internal networks
	var natTable *nftables.Table
	tables, err = conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == nftNatTableName && t.Family == nftables.TableFamilyINet {
			natTable = t
			break
		}
	}
	if natTable == nil {
		natTable = &nftables.Table{
			Name:   nftNatTableName,
			Family: nftables.TableFamilyINet,
		}
		conn.AddTable(natTable)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nftables add nat table: %w", err)
		}
	}

	// --- Create postrouting chain ---
	// For SNAT/masquerade rules
	var postroutingChain *nftables.Chain
	chains, err = conn.ListChains()
	if err != nil {
		return fmt.Errorf("nftables list chains: %w", err)
	}
	for _, c := range chains {
		if c.Table.Name == natTable.Name && c.Table.Family == natTable.Family && c.Name == nftPostroutingChain {
			postroutingChain = c
			break
		}
	}
	if postroutingChain == nil {
		policy := nftables.ChainPolicyAccept
		postroutingChain = &nftables.Chain{
			Name:     nftPostroutingChain,
			Table:    natTable,
			Hooknum:  nftables.ChainHookPostrouting,
			Priority: nftables.ChainPriorityNATSource,
			Type:     nftables.ChainTypeNAT,
			Policy:   &policy,
		}
		conn.AddChain(postroutingChain)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nftables add postrouting chain: %w", err)
		}
	}

	// --- Add masquerade rule ---
	// Traffic from WireGuard interface gets masqueraded
	rules, err = conn.GetRules(natTable, postroutingChain)
	if err != nil {
		return fmt.Errorf("nftables get rules: %w", err)
	}
	hasMasq := false
	for _, rule := range rules {
		var matchesIface, matchesMasq bool
		for _, e := range rule.Exprs {
			switch exp := e.(type) {
			case *expr.Cmp:
				if bytes.Equal(exp.Data, []byte(m.iface+"\x00")) {
					matchesIface = true
				}
			case *expr.Masq:
				matchesMasq = true
			}
		}
		if matchesIface && matchesMasq {
			hasMasq = true
			break
		}
	}
	if !hasMasq {
		conn.AddRule(&nftables.Rule{
			Table: natTable,
			Chain: postroutingChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: iifRegister},
				&expr.Cmp{Op: expr.CmpOpEq, Register: iifRegister, Data: []byte(m.iface + "\x00")},
				&expr.Masq{},
			},
		})
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("nftables add masquerade rule: %w", err)
		}
	}

	return nil
}

// ApplyPolicies updates the firewall rules based on the given policies.
// It flushes existing rules and rebuilds them from scratch.
func (m *Manager) ApplyPolicies(policies []controlplane.Policy) error {
	conn := &nftables.Conn{}

	// Flush existing rules in policy chain
	conn.FlushChain(m.policyChain)

	// --- Add logging rule ---
	// All traffic through this chain gets logged via nflog
	conn.AddRule(&nftables.Rule{
		Table: m.table,
		Chain: m.policyChain,
		Exprs: []expr.Any{
			&expr.Log{Group: DefaultLoggingGroup, Key: 1 << 1},
		},
	})

	// --- Build policy rules ---
	// For each policy in enforce mode, create accept rules for allowed src->dst pairs
	hasEnforceRules := false
	for _, policy := range policies {
		// Parse source CIDRs (client's allowed IPs)
		srcNets := make([]*net.IPNet, 0, len(policy.AllowedIPs))
		for _, cidr := range policy.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("parse allowed_ips: %w", err)
			}
			if ipNet.IP.To4() == nil {
				continue // Skip IPv6
			}
			srcNets = append(srcNets, ipNet)
		}

		// For each target in enforce mode, create rules
		for _, target := range policy.AllowedCIDRs {
			if target.Mode != controlplane.ModeEnforce {
				continue
			}

			_, dstNet, err := net.ParseCIDR(target.CIDR)
			if err != nil {
				return fmt.Errorf("parse allowed_cidrs: %w", err)
			}
			if dstNet.IP.To4() == nil {
				continue // Skip IPv6
			}

			// Create rule for each src->dst pair
			for _, srcNet := range srcNets {
				// Build match expressions for src and dst CIDR
				// Each CIDR match requires: payload load, bitwise mask, compare
				exprs := []expr.Any{
					// Match source IP
					&expr.Payload{DestRegister: srcAddrRegister, Base: expr.PayloadBaseNetworkHeader, Offset: ipv4SrcAddrOffset, Len: 4},
					&expr.Bitwise{SourceRegister: srcAddrRegister, DestRegister: srcAddrRegister, Len: 4, Mask: srcNet.Mask, Xor: []byte{0, 0, 0, 0}},
					&expr.Cmp{Op: expr.CmpOpEq, Register: srcAddrRegister, Data: srcNet.IP.To4()},
					// Match destination IP
					&expr.Payload{DestRegister: dstAddrRegister, Base: expr.PayloadBaseNetworkHeader, Offset: ipv4DstAddrOffset, Len: 4},
					&expr.Bitwise{SourceRegister: dstAddrRegister, DestRegister: dstAddrRegister, Len: 4, Mask: dstNet.Mask, Xor: []byte{0, 0, 0, 0}},
					&expr.Cmp{Op: expr.CmpOpEq, Register: dstAddrRegister, Data: dstNet.IP.To4()},
					// Accept matching traffic
					&expr.Verdict{Kind: expr.VerdictAccept},
				}
				conn.AddRule(&nftables.Rule{
					Table: m.table,
					Chain: m.policyChain,
					Exprs: exprs,
				})
				hasEnforceRules = true
			}
		}
	}

	// --- Add default drop rule ---
	// If any enforce rules exist, drop non-matching traffic
	if hasEnforceRules {
		conn.AddRule(&nftables.Rule{
			Table: m.table,
			Chain: m.policyChain,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	return nil
}
