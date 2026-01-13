package firewall

import (
	"bytes"
	"fmt"
	"net"

	"migration-to-zero-trust/wg-server/internal/config"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	nftTableName      = "filter"
	nftBaseChainName  = "forward"
	nftPolicyChain    = "wg-authz"
	nflogPrefix       = "wg"
	iifRegister       = 1
	srcAddrRegister   = 2
	dstAddrRegister   = 3
	ipv4SrcAddrOffset = 12
	ipv4DstAddrOffset = 16
)

func Apply(cfg config.Config) error {
	if cfg.Authz.Mode != config.AuthzModeEnforce && !cfg.Logging.Enabled {
		return nil
	}

	conn := &nftables.Conn{}

	table, err := ensureTable(conn)
	if err != nil {
		return err
	}

	baseChain, err := ensureBaseChain(conn, table)
	if err != nil {
		return err
	}

	policyChain, err := ensurePolicyChain(conn, table)
	if err != nil {
		return err
	}

	if err := ensureJumpRule(conn, table, baseChain, cfg.WG.Iface, policyChain.Name); err != nil {
		return err
	}

	conn.FlushChain(policyChain)

	if cfg.Logging.Enabled {
		conn.AddRule(buildLogRule(table, policyChain, uint16(cfg.Logging.Group)))
	}

	if cfg.Authz.Mode == config.AuthzModeEnforce {
		rules, err := buildPolicyRules(cfg, table, policyChain)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			conn.AddRule(rule)
		}
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: policyChain,
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
				Key:   (1 << unix.NFTA_LOG_GROUP) | (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_FLAGS),
				Group: group,
				Flags: expr.LogFlagsNFLog,
				Data:  []byte(nflogPrefix),
			},
		},
	}
}

func buildPolicyRules(cfg config.Config, table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	peerMap := make(map[string][]*net.IPNet, len(cfg.WG.Peers))
	for _, peer := range cfg.WG.Peers {
		for _, cidr := range peer.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("peer allowed_ips parse: %w", err)
			}
			if ipNet.IP.To4() == nil {
				return nil, fmt.Errorf("peer allowed_ips must be IPv4 for policy enforcement: %s", cidr)
			}
			peerMap[peer.PublicKey] = append(peerMap[peer.PublicKey], ipNet)
		}
	}

	var rules []*nftables.Rule
	for _, rule := range cfg.Policy.Rules {
		srcNets := peerMap[rule.ClientID]
		for _, dstCIDR := range rule.AllowedCIDRs {
			_, dstNet, err := net.ParseCIDR(dstCIDR)
			if err != nil {
				return nil, fmt.Errorf("policy allowed_cidrs parse: %w", err)
			}
			if dstNet.IP.To4() == nil {
				return nil, fmt.Errorf("policy allowed_cidrs must be IPv4: %s", dstCIDR)
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

	if len(rules) == 0 {
		return nil, fmt.Errorf("policy rules did not produce any nftables rules")
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
