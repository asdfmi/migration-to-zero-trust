package firewall

import (
	"bytes"
	"fmt"
	"net"

	"migration-to-zero-trust/wg-server/internal/controlplane"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	nftTableName      = "filter"
	nftNatTableName   = "nat"
	nftBaseChainName  = "forward"
	nftPolicyChain    = "wg-authz"
	nftPostroutingChain = "postrouting"
	nflogPrefix       = "wg"
	iifRegister       = 1
	srcAddrRegister   = 2
	dstAddrRegister   = 3
	ipv4SrcAddrOffset = 12
	ipv4DstAddrOffset = 16
)

const defaultLoggingGroup = 100

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

func (m *Manager) Setup() error {
	conn := &nftables.Conn{}

	table, err := ensureTable(conn)
	if err != nil {
		return err
	}
	m.table = table

	baseChain, err := ensureBaseChain(conn, table)
	if err != nil {
		return err
	}

	policyChain, err := ensurePolicyChain(conn, table)
	if err != nil {
		return err
	}
	m.policyChain = policyChain

	if err := ensureJumpRule(conn, table, baseChain, m.iface, policyChain.Name); err != nil {
		return err
	}

	// Setup NAT/masquerade for traffic from wg interface
	if err := m.setupNAT(conn); err != nil {
		return err
	}

	return nil
}

func (m *Manager) ApplyPolicies(policies []controlplane.Policy) error {
	conn := &nftables.Conn{}

	conn.FlushChain(m.policyChain)

	// Always enable logging
	conn.AddRule(buildLogRule(m.table, m.policyChain, defaultLoggingGroup))

	// Build rules for enforce mode targets and check if any exist
	hasEnforceRules := false
	rules, err := buildPolicyRules(policies, m.table, m.policyChain)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		conn.AddRule(rule)
		hasEnforceRules = true
	}

	// If any enforce rules exist, add drop rule at the end
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

func ensureTable(conn *nftables.Conn) (*nftables.Table, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("nftables list tables: %w", err)
	}
	for _, table := range tables {
		if table.Name == nftTableName && table.Family == nftables.TableFamilyINet {
			return table, nil
		}
	}

	table := &nftables.Table{
		Name:   nftTableName,
		Family: nftables.TableFamilyINet,
	}
	conn.AddTable(table)
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("nftables add table: %w", err)
	}
	return table, nil
}

func ensureBaseChain(conn *nftables.Conn, table *nftables.Table) (*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("nftables list chains: %w", err)
	}
	for _, chain := range chains {
		if chain.Table.Name == table.Name && chain.Table.Family == table.Family && chain.Name == nftBaseChainName {
			return chain, nil
		}
	}

	policy := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     nftBaseChainName,
		Table:    table,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policy,
	}
	conn.AddChain(chain)
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("nftables add chain: %w", err)
	}
	return chain, nil
}

func ensurePolicyChain(conn *nftables.Conn, table *nftables.Table) (*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("nftables list chains: %w", err)
	}
	for _, chain := range chains {
		if chain.Table.Name == table.Name && chain.Table.Family == table.Family && chain.Name == nftPolicyChain {
			return chain, nil
		}
	}

	chain := &nftables.Chain{
		Name:  nftPolicyChain,
		Table: table,
	}
	conn.AddChain(chain)
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("nftables add chain: %w", err)
	}
	return chain, nil
}

func ensureJumpRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, iface string, targetChain string) error {
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return fmt.Errorf("nftables get rules: %w", err)
	}
	if hasJumpRule(rules, iface, targetChain) {
		return nil
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: iifRegister,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: iifRegister,
				Data:     []byte(iface + "\x00"),
			},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: targetChain,
			},
		},
	}

	conn.InsertRule(rule)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables insert jump rule: %w", err)
	}
	return nil
}

func hasJumpRule(rules []*nftables.Rule, iface string, targetChain string) bool {
	var hasIface bool
	var hasJump bool
	for _, rule := range rules {
		for _, e := range rule.Exprs {
			switch exp := e.(type) {
			case *expr.Meta:
				if exp.Key == expr.MetaKeyIIFNAME {
					hasIface = true
				}
			case *expr.Cmp:
				if bytes.Equal(exp.Data, []byte(iface+"\x00")) {
					hasIface = true
				}
			case *expr.Verdict:
				if exp.Kind == expr.VerdictJump && exp.Chain == targetChain {
					hasJump = true
				}
			}
		}
	}
	return hasIface && hasJump
}

func buildLogRule(table *nftables.Table, chain *nftables.Chain, group uint16) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Log{
				Group: group,
				Key:   1 << 1, // NFTA_LOG_GROUP
			},
		},
	}
}

func buildPolicyRules(policies []controlplane.Policy, table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	var rules []*nftables.Rule

	for _, policy := range policies {
		srcNets := make([]*net.IPNet, 0, len(policy.AllowedIPs))
		for _, cidr := range policy.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("parse allowed_ips: %w", err)
			}
			if ipNet.IP.To4() == nil {
				continue
			}
			srcNets = append(srcNets, ipNet)
		}

		for _, target := range policy.AllowedCIDRs {
			// Only create rules for enforce mode
			if target.Mode != "enforce" {
				continue
			}

			_, dstNet, err := net.ParseCIDR(target.CIDR)
			if err != nil {
				return nil, fmt.Errorf("parse allowed_cidrs: %w", err)
			}
			if dstNet.IP.To4() == nil {
				continue
			}

			for _, srcNet := range srcNets {
				exprs := make([]expr.Any, 0, 7)
				exprs = append(exprs, matchIPv4CIDR(ipv4SrcAddrOffset, srcAddrRegister, srcNet)...)
				exprs = append(exprs, matchIPv4CIDR(ipv4DstAddrOffset, dstAddrRegister, dstNet)...)
				exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})

				rules = append(rules, &nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: exprs,
				})
			}
		}
	}

	return rules, nil
}

func matchIPv4CIDR(offset uint32, reg uint32, ipNet *net.IPNet) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: reg,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: reg,
			DestRegister:   reg,
			Len:            4,
			Mask:           ipNet.Mask,
			Xor:            []byte{0x0, 0x0, 0x0, 0x0},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: reg,
			Data:     ipNet.IP.To4(),
		},
	}
}

func (m *Manager) setupNAT(conn *nftables.Conn) error {
	// Create or get nat table
	natTable := &nftables.Table{
		Name:   nftNatTableName,
		Family: nftables.TableFamilyINet,
	}
	conn.AddTable(natTable)

	// Create postrouting chain
	policy := nftables.ChainPolicyAccept
	postroutingChain := &nftables.Chain{
		Name:     nftPostroutingChain,
		Table:    natTable,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Type:     nftables.ChainTypeNAT,
		Policy:   &policy,
	}
	conn.AddChain(postroutingChain)

	// Add masquerade rule for traffic from wg interface
	// iifname "wg0" masquerade
	conn.AddRule(&nftables.Rule{
		Table: natTable,
		Chain: postroutingChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: iifRegister,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: iifRegister,
				Data:     []byte(m.iface + "\x00"),
			},
			&expr.Masq{},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables setup NAT: %w", err)
	}

	return nil
}
