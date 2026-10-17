package control

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const firewallTable = "netcontrol"

func firewallExpressions(rule FirewallRule) []expr.Any {
	var result []expr.Any
	if rule.Source != "" || rule.Destination != "" {
		family := byte(unix.NFPROTO_IPV4)
		prefix := rule.Source
		if prefix == "" {
			prefix = rule.Destination
		}
		p, _ := netip.ParsePrefix(prefix)
		if p.Addr().Is6() {
			family = unix.NFPROTO_IPV6
		}
		result = addressExpressions(rule.Source, rule.Destination, family)
	}
	verdict := expr.VerdictAccept
	if rule.Action == "drop" {
		verdict = expr.VerdictDrop
	}
	return append(result, &expr.Verdict{Kind: verdict})
}

func addressExpressions(source, destination string, family byte) []expr.Any {
	result := []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}}}
	for i, prefix := range []string{source, destination} {
		if prefix == "" {
			continue
		}
		p, _ := netip.ParsePrefix(prefix)
		length, offset := uint32(4), uint32(12+4*i)
		if family == unix.NFPROTO_IPV6 {
			length, offset = 16, uint32(8+16*i)
		}
		result = append(result,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: []byte(net.CIDRMask(p.Bits(), p.Addr().BitLen())), Xor: make([]byte, length)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Addr().AsSlice()})
	}
	return result
}

func masqueradeExpressions(rule MasqueradeRule) []expr.Any {
	family := byte(unix.NFPROTO_IPV4)
	if rule.Family == "ipv6" {
		family = unix.NFPROTO_IPV6
	}
	result := addressExpressions(rule.Source, "", family)
	name := make([]byte, unix.IFNAMSIZ)
	copy(name, rule.OutInterface)
	return append(result, &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name}, &expr.Masq{})
}

func ownedFirewallTable(conn *nftables.Conn) (*nftables.Table, error) {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, err
	}
	for _, table := range tables {
		if table.Name == firewallTable {
			return table, nil
		}
	}
	return nil, nil
}

func reconcileFirewall(f Firewall) error {
	var policyRules, metadataRules []*nftables.Rule
	if f.Policies != nil {
		if len(f.Rules) != 0 {
			return fmt.Errorf("cannot mix legacy and host/interface firewall rules")
		}
		var err error
		policyRules, err = policyForwardRules(f.Policies)
		if err != nil {
			return err
		}
		metadataRules, err = policyMetadataRules(f.Policies)
		if err != nil {
			return err
		}
	}
	conn := &nftables.Conn{}
	table, err := ownedFirewallTable(conn)
	if err != nil {
		return err
	}
	if table != nil {
		conn.DelTable(table)
	}
	table = conn.AddTable(&nftables.Table{Name: firewallTable, Family: nftables.TableFamilyINet})
	policy := nftables.ChainPolicyAccept
	if f.Policy == "drop" {
		policy = nftables.ChainPolicyDrop
	}
	chain := conn.AddChain(&nftables.Chain{Name: "forward", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &policy})
	if f.Policies != nil {
		metadataChain := conn.AddChain(&nftables.Chain{Name: firewallMetadataChain, Table: table})
		for _, rule := range metadataRules {
			rule.Table, rule.Chain = table, metadataChain
			conn.AddRule(rule)
		}
		for _, rule := range policyRules {
			rule.Table, rule.Chain = table, chain
			conn.AddRule(rule)
		}
	}
	for _, r := range f.Rules {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: firewallExpressions(r), UserData: data})
	}
	if len(f.NAT.Masquerade) != 0 {
		accept := nftables.ChainPolicyAccept
		postrouting := conn.AddChain(&nftables.Chain{Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept})
		for _, r := range f.NAT.Masquerade {
			data, err := json.Marshal(r)
			if err != nil {
				return err
			}
			conn.AddRule(&nftables.Rule{Table: table, Chain: postrouting, Exprs: masqueradeExpressions(r), UserData: data})
		}
	}
	// The delete/recreate and all rules are sent in ONE nftables batch.
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("atomic nftables batch: %w", err)
	}
	return nil
}

func observeFirewall() (Firewall, error) {
	f := EmptyConfig().Firewall
	conn := &nftables.Conn{}
	table, err := ownedFirewallTable(conn)
	if err != nil || table == nil {
		return f, err
	}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return f, err
	}
	var chain, postrouting, metadataChain *nftables.Chain
	for _, c := range chains {
		if c.Table.Name != firewallTable {
			continue
		}
		if c.Name == firewallMetadataChain {
			if metadataChain != nil || c.Hooknum != nil || c.Priority != nil || c.Policy != nil || c.Device != "" || c.Type != "" {
				return f, fmt.Errorf("owned firewall metadata chain has unsupported settings")
			}
			metadataChain = c
			continue
		}
		if c.Hooknum == nil || c.Priority == nil || c.Policy == nil || c.Device != "" {
			return f, fmt.Errorf("owned nftables table contains unsupported chains")
		}
		switch c.Name {
		case "forward":
			if chain != nil || c.Type != nftables.ChainTypeFilter ||
				*c.Hooknum != *nftables.ChainHookForward || *c.Priority != *nftables.ChainPriorityFilter {
				return f, fmt.Errorf("owned nftables forward chain has unsupported settings")
			}
			chain = c
		case "postrouting":
			if postrouting != nil || c.Type != nftables.ChainTypeNAT ||
				*c.Hooknum != *nftables.ChainHookPostrouting || *c.Priority != *nftables.ChainPriorityNATSource || *c.Policy != nftables.ChainPolicyAccept {
				return f, fmt.Errorf("owned nftables postrouting chain has unsupported settings")
			}
			postrouting = c
		default:
			return f, fmt.Errorf("owned nftables table contains unsupported chains")
		}
	}
	if chain == nil {
		return f, fmt.Errorf("owned nftables table is missing forward chain")
	}
	if *chain.Policy == nftables.ChainPolicyDrop {
		f.Policy = "drop"
	} else if *chain.Policy != nftables.ChainPolicyAccept {
		return f, fmt.Errorf("unsupported firewall policy")
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		return f, err
	}
	if len(sets) != 0 {
		return f, fmt.Errorf("owned firewall table contains unexpected sets")
	}
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return f, err
	}
	if metadataChain != nil {
		metadata, err := conn.GetRules(table, metadataChain)
		if err != nil {
			return f, err
		}
		f.Policies, err = observePolicyFirewall(metadata, rules)
		if err != nil {
			return f, err
		}
	} else {
		for _, rule := range rules {
			var r FirewallRule
			if err := json.Unmarshal(rule.UserData, &r); err != nil {
				return f, fmt.Errorf("owned firewall rule has invalid metadata")
			}
			check := EmptyConfig()
			check.Firewall.Rules = []FirewallRule{r}
			if err := check.Validate(); err != nil {
				return f, fmt.Errorf("owned firewall rule metadata: %w", err)
			}
			if !reflect.DeepEqual(rule.Exprs, firewallExpressions(r)) {
				return f, fmt.Errorf("owned firewall rule expressions differ from metadata")
			}
			f.Rules = append(f.Rules, r)
		}
	}
	if postrouting != nil {
		rules, err := conn.GetRules(table, postrouting)
		if err != nil {
			return f, err
		}
		for _, rule := range rules {
			var r MasqueradeRule
			if err := json.Unmarshal(rule.UserData, &r); err != nil {
				return f, fmt.Errorf("owned masquerade rule has invalid metadata")
			}
			if err := r.validate(nil); err != nil {
				return f, fmt.Errorf("owned masquerade rule metadata: %w", err)
			}
			if !reflect.DeepEqual(rule.Exprs, masqueradeExpressions(r)) {
				return f, fmt.Errorf("owned masquerade rule expressions differ from metadata")
			}
			f.NAT.Masquerade = append(f.NAT.Masquerade, r)
		}
	}
	return f, nil
}
