package control

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const firewallMetadataChain = "policy_metadata"
const firewallMetadataChunk = 240

func policyExpressions(rule compiledFirewallRule) []expr.Any {
	if rule.EstablishedRelated {
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}
	}
	base := firewallExpressions(FirewallRule{Source: rule.Source, Destination: rule.Destination, Action: rule.Action})
	result := append([]expr.Any{}, base[:len(base)-1]...)
	if rule.InInterface != "" {
		name := make([]byte, unix.IFNAMSIZ)
		copy(name, rule.InInterface)
		result = append(result, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name})
	}
	if rule.Protocol != "" {
		protocol := byte(unix.IPPROTO_TCP)
		if rule.Protocol == "udp" {
			protocol = unix.IPPROTO_UDP
		}
		result = append(result, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}})
	}
	if rule.DestinationPort != 0 {
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(rule.DestinationPort))
		result = append(result, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port})
	}
	return append(result, base[len(base)-1])
}

func policyMetadataExpressions() []expr.Any {
	return []expr.Any{&expr.Immediate{Register: 1, Data: []byte{0, 0, 0, 0}}}
}

// Keep the abstract inventory in an unhooked chain, not in the packet hot path.
// nftables caps each rule's userdata at 256 bytes.
func policyMetadataRules(p *FirewallPolicies) ([]*nftables.Rule, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFirewallPolicyMetadata {
		return nil, fmt.Errorf("firewall policy metadata too large")
	}
	var rules []*nftables.Rule
	for offset := 0; offset < len(data); offset += firewallMetadataChunk {
		end := min(offset+firewallMetadataChunk, len(data))
		header := []byte{'n', 'c', 'p', 1}
		header = binary.BigEndian.AppendUint32(header, uint32(len(rules)))
		rules = append(rules, &nftables.Rule{Exprs: policyMetadataExpressions(), UserData: append(header, data[offset:end]...)})
	}
	return rules, nil
}

func policyForwardRules(p *FirewallPolicies) ([]*nftables.Rule, error) {
	compiled, err := compileFirewallPolicies(p)
	if err != nil {
		return nil, err
	}
	result := make([]*nftables.Rule, 0, len(compiled))
	for _, rule := range compiled {
		result = append(result, &nftables.Rule{Exprs: policyExpressions(rule)})
	}
	return result, nil
}

func observePolicyFirewall(metadata, forward []*nftables.Rule) (*FirewallPolicies, error) {
	var data []byte
	if len(metadata) == 0 || len(metadata) > (maxFirewallPolicyMetadata+firewallMetadataChunk-1)/firewallMetadataChunk {
		return nil, fmt.Errorf("invalid firewall policy metadata length")
	}
	for i, rule := range metadata {
		if len(rule.UserData) < 9 || len(rule.UserData) > firewallMetadataChunk+8 ||
			!bytes.Equal(rule.UserData[:4], []byte{'n', 'c', 'p', 1}) ||
			binary.BigEndian.Uint32(rule.UserData[4:8]) != uint32(i) ||
			!reflect.DeepEqual(rule.Exprs, policyMetadataExpressions()) {
			return nil, fmt.Errorf("invalid firewall policy metadata chunk")
		}
		data = append(data, rule.UserData[8:]...)
	}
	if len(data) > maxFirewallPolicyMetadata {
		return nil, fmt.Errorf("firewall policy metadata too large")
	}
	var policies FirewallPolicies
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("decode firewall policy metadata: %w", err)
	}
	expectedMetadata, err := policyMetadataRules(&policies)
	if err != nil {
		return nil, err
	}
	if len(expectedMetadata) != len(metadata) {
		return nil, fmt.Errorf("noncanonical firewall policy metadata")
	}
	for i := range metadata {
		if !bytes.Equal(metadata[i].UserData, expectedMetadata[i].UserData) {
			return nil, fmt.Errorf("noncanonical firewall policy metadata")
		}
	}
	expected, err := policyForwardRules(&policies)
	if err != nil {
		return nil, fmt.Errorf("invalid firewall policies: %w", err)
	}
	if len(expected) != len(forward) {
		return nil, fmt.Errorf("owned firewall rule count differs from policies")
	}
	for i := range forward {
		if len(forward[i].UserData) != 0 || !reflect.DeepEqual(forward[i].Exprs, expected[i].Exprs) {
			return nil, fmt.Errorf("owned firewall rule %d differs from policies", i)
		}
	}
	return &policies, nil
}
