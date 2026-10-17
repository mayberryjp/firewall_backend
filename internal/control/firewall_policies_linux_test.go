package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestPolicyExpressionsMatchIngressProtocolAndDestinationPort(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		r := compiledFirewallRule{Source: "2001:db8::10/128", Destination: "2001:db8::20/128", InInterface: "lan", Protocol: protocol, DestinationPort: 8443, Action: "drop"}
		expressions := policyExpressions(r)
		ingress, transport, port := false, false, false
		for i, value := range expressions {
			switch v := value.(type) {
			case *expr.Meta:
				if v.Key == expr.MetaKeyIIFNAME {
					cmp, ok := expressions[i+1].(*expr.Cmp)
					expected := make([]byte, unix.IFNAMSIZ)
					copy(expected, "lan")
					ingress = ok && cmp.Op == expr.CmpOpEq && bytes.Equal(cmp.Data, expected)
				}
				if v.Key == expr.MetaKeyL4PROTO {
					cmp, ok := expressions[i+1].(*expr.Cmp)
					want := byte(unix.IPPROTO_TCP)
					if protocol == "udp" {
						want = unix.IPPROTO_UDP
					}
					transport = ok && bytes.Equal(cmp.Data, []byte{want})
				}
			case *expr.Payload:
				if v.Base == expr.PayloadBaseTransportHeader {
					cmp, ok := expressions[i+1].(*expr.Cmp)
					port = ok && v.Offset == 2 && v.Len == 2 && len(cmp.Data) == 2 && binary.BigEndian.Uint16(cmp.Data) == 8443
				}
			}
		}
		verdict, ok := expressions[len(expressions)-1].(*expr.Verdict)
		if !ingress || !transport || !port || !ok || verdict.Kind != expr.VerdictDrop {
			t.Fatalf("incomplete %s match: %+v", protocol, expressions)
		}
	}
	stateful := policyExpressions(compiledFirewallRule{EstablishedRelated: true, Action: "accept"})
	ct, ok := stateful[0].(*expr.Ct)
	if !ok || ct.Key != expr.CtKeySTATE {
		t.Fatal("missing conntrack state read")
	}
	mask, ok := stateful[1].(*expr.Bitwise)
	if !ok || !bytes.Equal(mask.Mask, binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)) {
		t.Fatal("incorrect state mask")
	}
	cmp, ok := stateful[2].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpNeq || !bytes.Equal(cmp.Data, make([]byte, 4)) {
		t.Fatal("state mask must match nonzero established/related")
	}
	verdict, ok := stateful[3].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatal("missing stateful accept")
	}
}

func TestPolicyMetadataRoundTripAndDriftDetection(t *testing.T) {
	p := hostPolicyConfig().Firewall.Policies
	metadata, err := policyMetadataRules(p)
	if err != nil {
		t.Fatal(err)
	}
	forward, err := policyForwardRules(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) < 2 {
		t.Fatal("test must span multiple metadata chunks")
	}
	for _, rule := range metadata {
		if len(rule.UserData) > 256 {
			t.Fatal("nftables userdata limit exceeded")
		}
	}
	observed, err := observePolicyFirewall(metadata, forward)
	if err != nil || !reflect.DeepEqual(p, observed) {
		t.Fatalf("metadata round trip: %+v %v", observed, err)
	}
	mutations := map[string]func([]*nftables.Rule, []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule){
		"missing metadata": func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) { return nil, f },
		"metadata order":   func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) { m[0], m[1] = m[1], m[0]; return m, f },
		"metadata expression": func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) {
			m[0].Exprs = []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
			return m, f
		},
		"invalid metadata header": func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) { m[0].UserData[0] = 'x'; return m, f },
		"missing forward rule":    func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) { return m, f[1:] },
		"forward order":           func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) { f[0], f[1] = f[1], f[0]; return m, f },
		"forward expression": func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) {
			f[0].Exprs = []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
			return m, f
		},
		"unexpected userdata": func(m, f []*nftables.Rule) ([]*nftables.Rule, []*nftables.Rule) {
			f[0].UserData = []byte("foreign")
			return m, f
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m, err := policyMetadataRules(p)
			if err != nil {
				t.Fatal(err)
			}
			f, err := policyForwardRules(p)
			if err != nil {
				t.Fatal(err)
			}
			m, f = mutate(m, f)
			if _, err := observePolicyFirewall(m, f); err == nil {
				t.Fatal("firewall drift accepted")
			}
		})
	}
}

func TestLinuxHostPolicyTransactionRoundTrip(t *testing.T) {
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
	e := testEngine(t, testStore(t), adapter)
	c := hostPolicyConfig()
	tx := submit(t, e, 0, c)
	view, err := e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("native policy readback: %+v %v", view, err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	changed := Clone(c)
	changed.Firewall.Policies.Hosts[0].Addresses = []string{"192.0.2.30"}
	tx = submit(t, e, 1, changed)
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("native policy rollback: %+v %v", view, err)
	}
	err = adapter.(*linuxAdapter).inNamespace(context.Background(), func() error {
		conn := &nftables.Conn{}
		table, err := ownedFirewallTable(conn)
		if err != nil {
			return err
		}
		rules, err := conn.GetRules(table, &nftables.Chain{Name: "forward", Table: table})
		if err != nil {
			return err
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
		t.Fatal("removed native policy rule did not produce an observation error")
	}
}
