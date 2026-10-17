package control

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestAllowAllICMPExpressions(t *testing.T) {
	want := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
	rule := allowAllICMPRule()
	if !reflect.DeepEqual(rule.Exprs, want) || string(rule.UserData) != allowAllICMPMetadata {
		t.Fatalf("must accept only IPv4 protocol 1 without interface, address, or ICMP type restrictions: %+v", rule)
	}
}

func TestObserveICMPFirewallDetectsDrift(t *testing.T) {
	legacy := &nftables.Rule{Exprs: firewallExpressions(FirewallRule{Action: "drop"})}
	enabled, remaining, err := observeICMPFirewall([]*nftables.Rule{legacy}, nil, nil)
	if err != nil || enabled || len(remaining) != 1 || remaining[0] != legacy {
		t.Fatalf("legacy rules changed: %v %+v %v", enabled, remaining, err)
	}
	forward := []*nftables.Rule{allowAllICMPRule(), legacy}
	local := []*nftables.Rule{allowAllICMPRule()}
	enabled, remaining, err = observeICMPFirewall(forward, local, local)
	if err != nil || !enabled || len(remaining) != 1 || remaining[0] != legacy {
		t.Fatalf("ICMP exception not separated from ordered rules: %v %+v %v", enabled, remaining, err)
	}
	cases := map[string]func([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule){
		"missing forward": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			return f[1:], i, o
		},
		"missing input": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			return f, nil, o
		},
		"missing output": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			return f, i, nil
		},
		"extra input": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			return f, append(i, allowAllICMPRule()), o
		},
		"reordered forward": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			f[0], f[1] = f[1], f[0]
			return f, i, o
		},
		"wrong protocol": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			f[0].Exprs[3].(*expr.Cmp).Data = []byte{unix.IPPROTO_ICMPV6}
			return f, i, o
		},
		"changed input verdict": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			i[0].Exprs[4] = &expr.Verdict{Kind: expr.VerdictDrop}
			return f, i, o
		},
		"changed output metadata": func(f, i, o []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule, []*nftables.Rule) {
			o[0].UserData = []byte("foreign")
			return f, i, o
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, i, o := mutate([]*nftables.Rule{allowAllICMPRule(), legacy},
				[]*nftables.Rule{allowAllICMPRule()}, []*nftables.Rule{allowAllICMPRule()})
			if _, _, err := observeICMPFirewall(f, i, o); err == nil {
				t.Fatal("ICMP rule drift accepted")
			}
		})
	}
}

func TestLinuxICMPDefaultMigrationPreservesUnrelatedDrift(t *testing.T) {
	namespace := extensionNamespace(t)
	adapter, err := NewLinuxAdapter(namespace, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Error(err)
		}
	})
	actual := EmptyConfig()
	disabled := false
	actual.Firewall.AllowAllICMP = &disabled
	actual.Firewall.Policy = "drop"
	if err := adapter.Reconcile(context.Background(), actual); err != nil {
		t.Fatal(err)
	}
	expected := EmptyConfig().Firewall
	err = adapter.(*linuxAdapter).migrateICMPDefault(context.Background(), expected)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("unrelated firewall drift was not rejected: %v", err)
	}
	observed, err := adapter.Observe(context.Background(), actual)
	if err != nil || !Equal(observed, actual) {
		t.Fatalf("migration overwrote drift: %+v %v", observed, err)
	}
}

func TestLinuxICMPTransactionAndDefaultMigration(t *testing.T) {
	for _, hostPolicies := range []bool{false, true} {
		name := "legacy"
		if hostPolicies {
			name = "host policies"
		}

		t.Run(name, func(t *testing.T) {
			namespace := extensionNamespace(t)
			adapter, err := NewLinuxAdapter(namespace, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := adapter.Close(); err != nil {
					t.Error(err)
				}
			})
			store := testStore(t)
			e := testEngine(t, store, adapter)
			c := EmptyConfig()
			c.Firewall.Policy = "drop"
			if hostPolicies {
				c.Firewall.Policies = &FirewallPolicies{Interfaces: []InterfacePolicy{}, Hosts: []FirewallHost{}}
			} else {
				c.Firewall.Rules = []FirewallRule{{Action: "drop"}}
			}
			tx := submit(t, e, 0, c)
			if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
				t.Fatal(err)
			}
			check := func(want bool) {
				t.Helper()
				view, err := e.View(context.Background())
				if err != nil || view.Drift || view.Observed.Firewall.allowsAllICMP() != want {
					t.Fatalf("native ICMP readback: %+v %v", view, err)
				}
			}
			check(true)
			disabled := Clone(c)
			value := false
			disabled.Firewall.AllowAllICMP = &value
			tx = submit(t, e, 1, disabled)
			check(false)
			if _, err := e.Rollback(tx.ID, "test"); err != nil {
				t.Fatal(err)
			}
			check(true)
			// Recreate an older installation: no ICMP rules and no saved setting.
			if err := adapter.Reconcile(context.Background(), disabled); err != nil {
				t.Fatal(err)
			}
			state := e.Snapshot()
			state.Desired.Firewall.AllowAllICMP = nil
			for _, transaction := range state.Transactions {
				transaction.Previous.Firewall.AllowAllICMP = nil
				transaction.Candidate.Firewall.AllowAllICMP = nil
			}
			if err := store.Save(state); err != nil {
				t.Fatal(err)
			}
			e = testEngine(t, store, adapter)
			check(true)
			err = adapter.(*linuxAdapter).inNamespace(context.Background(), func() error {
				conn := &nftables.Conn{}
				table, err := ownedFirewallTable(conn)
				if err != nil {
					return err
				}
				rules, err := conn.GetRules(table, &nftables.Chain{Name: "input", Table: table})
				if err != nil {
					return err
				}
				if len(rules) != 1 {
					t.Fatalf("expected exactly one ICMP input rule, got %d", len(rules))
				}
				if err := conn.DelRule(rules[0]); err != nil {
					return err
				}
				return conn.Flush()
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.View(context.Background()); err == nil {
				t.Fatal("missing local ICMP rule did not produce an observation error")
			}
		})
	}
}
