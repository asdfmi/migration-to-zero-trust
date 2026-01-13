package logging

import (
	"bytes"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	nftTableName  = "filter"
	nftChainName  = "forward"
	nflogPrefix   = "wg"
	nflogRegister = 1
)

func ensureNFLOGRule(conn *nftables.Conn, iface string, group uint16) error {
	table, err := ensureTable(conn)
	if err != nil {
		return err
	}

	chain, err := ensureChain(conn, table)
	if err != nil {
		return err
	}

	exists, err := hasNFLOGRule(conn, table, chain, iface, group)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: nflogRegister,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: nflogRegister,
				Data:     []byte(iface + "\x00"),
			},
			&expr.Log{
				Key:   (1 << unix.NFTA_LOG_GROUP) | (1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_FLAGS),
				Group: group,
				Flags: expr.LogFlagsNFLog,
				Data:  []byte(nflogPrefix),
			},
		},
	}

	conn.AddRule(rule)
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

func ensureChain(conn *nftables.Conn, table *nftables.Table) (*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("nftables list chains: %w", err)
	}
	for _, chain := range chains {
		if chain.Table.Name == table.Name && chain.Table.Family == table.Family && chain.Name == nftChainName {
			return chain, nil
		}
	}

	policy := nftables.ChainPolicyAccept
	chain := &nftables.Chain{
		Name:     nftChainName,
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

func hasNFLOGRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, iface string, group uint16) (bool, error) {
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return false, fmt.Errorf("nftables get rules: %w", err)
	}

	ifaceData := []byte(iface + "\x00")
	for _, rule := range rules {
		if ruleMatches(rule, ifaceData, group) {
			return true, nil
		}
	}
	return false, nil
}

func ruleMatches(rule *nftables.Rule, ifaceData []byte, group uint16) bool {
	var hasIface bool
	var hasLog bool
	for _, e := range rule.Exprs {
		switch exp := e.(type) {
		case *expr.Cmp:
			if exp.Op == expr.CmpOpEq && bytes.Equal(exp.Data, ifaceData) {
				hasIface = true
			}
		case *expr.Log:
			if exp.Group == group && string(exp.Data) == nflogPrefix {
				hasLog = true
			}
		}
	}
	return hasIface && hasLog
}
