package control

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const allowAllICMPMetadata = "netcontrol:allow_all_icmp:v1"

func (a *linuxAdapter) migrateICMPDefault(ctx context.Context, expected Firewall) error {
	return a.inNamespace(ctx, func() error {
		observed, err := observeFirewall()
		if err != nil {
			return err
		}
		// Only the new exception may change during an upgrade; preserve drift detection.
		before, target := EmptyConfig(), EmptyConfig()
		before.Firewall, target.Firewall = observed, Clone(expected)
		target.Firewall.AllowAllICMP = observed.AllowAllICMP
		if !Equal(before, target) {
			return fmt.Errorf("%w: firewall drift prevents ICMP default migration", ErrConflict)
		}
		return reconcileFirewall(expected)
	})
}

func allowAllICMPRule() *nftables.Rule {
	return &nftables.Rule{
		UserData: []byte(allowAllICMPMetadata),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
}

func observeICMPFirewall(forward, input, output []*nftables.Rule) (bool, []*nftables.Rule, error) {
	enabled := len(forward) != 0 && bytes.Equal(forward[0].UserData, []byte(allowAllICMPMetadata))
	if !enabled {
		if len(input) != 0 || len(output) != 0 {
			return false, nil, fmt.Errorf("owned ICMP chains differ from forward exception")
		}
		return false, forward, nil
	}
	if len(input) != 1 || len(output) != 1 {
		return false, nil, fmt.Errorf("owned ICMP exception requires one input and output rule")
	}
	expected := allowAllICMPRule()
	for _, rule := range []*nftables.Rule{forward[0], input[0], output[0]} {
		if !bytes.Equal(rule.UserData, expected.UserData) || !reflect.DeepEqual(rule.Exprs, expected.Exprs) {
			return false, nil, fmt.Errorf("owned ICMP rule differs from expected exception")
		}
	}
	return true, forward[1:], nil
}
