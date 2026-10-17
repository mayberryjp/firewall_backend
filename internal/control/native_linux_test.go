package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestOwnedRuleDecoderPreservesAction(t *testing.T) {
	for _, action := range []uint8{unix.RTN_UNICAST, unix.RTN_BLACKHOLE, unix.RTN_UNREACHABLE} {
		msg := nl.NewRtMsg()
		msg.Family, msg.Type = netlink.FAMILY_V4, action
		data := append([]byte(nil), msg.Serialize()...)
		data = append(data, nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(10000)).Serialize()...)
		data = append(data, nl.NewRtAttr(unix.RTA_TABLE, nl.Uint32Attr(10000)).Serialize()...)
		r, owned, err := decodeOwnedRule(data)
		if err != nil || !owned || r.Type != action {
			t.Fatalf("action %d: %+v %v", action, r, err)
		}
		if simpleRule(r) != (action == unix.RTN_UNICAST) {
			t.Fatalf("unsafe rule action treated as lookup: %d", action)
		}
	}
}

// This test creates and deletes only its own namespace. It never targets host networking.
func TestLinuxIsolatedTransaction(t *testing.T) {
	if os.Getenv("NETCONTROL_INTEGRATION") != "1" {
		t.Skip("requires explicit opt-in and Linux namespace/network administration capabilities")
	}
	namespace := fmt.Sprintf("nctest-%d-%d", os.Getpid(), time.Now().UnixNano())
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	created, createErr := netns.NewNamed(namespace)
	restoreErr := netns.Set(original)
	original.Close()
	if restoreErr != nil {
		t.Fatalf("restore namespace: %v", restoreErr)
	}
	runtime.UnlockOSThread()
	if createErr != nil {
		t.Fatal(createErr)
	}
	created.Close()
	t.Cleanup(func() {
		if err := netns.DeleteNamed(namespace); err != nil {
			t.Error(err)
		}
	})
	keys := t.TempDir()
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "wg0"), []byte(private.String()), 0600); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewLinuxAdapter(namespace, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Error(err)
		}
	})
	e := testEngine(t, testStore(t), adapter)
	c := candidate()
	c.Interfaces[0].Addresses = append(c.Interfaces[0].Addresses, "192.0.2.11/24")
	c.Interfaces = append(c.Interfaces, Interface{Name: "wg0", Kind: "wireguard", Role: "lan", MTU: 1420, Up: true, Addresses: []string{"2001:db8::1/64"}, WireGuard: &WireGuard{KeyRef: "wg0", ListenPort: 51820}})
	c.Routes = append(c.Routes, Route{Destination: "2001:db8:1::/64", Interface: "wg0", Table: 10001, Metric: 100})
	c.Rules = append(c.Rules, Rule{Priority: 10001, Source: "::/0", Table: 10001})
	c.Firewall.Rules = append(c.Firewall.Rules, FirewallRule{Source: "2001:db8::/32", Destination: "2001:db8:1::/64", Action: "accept"})
	c.Firewall.NAT.Masquerade = append(c.Firewall.NAT.Masquerade, MasqueradeRule{Family: "ipv6", Source: "2001:db8::/32", OutInterface: "wg0"})
	tx := submit(t, e, 0, c)
	v, err := e.View(context.Background())
	if err != nil || v.Drift || !Equal(v.Observed, c) {
		t.Fatalf("native observation: %+v %v", v, err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	sourcePort := probeMasqueradePacket(t, adapter, 0, 45678, true)
	unmatched := Clone(c)
	unmatched.Firewall.NAT.Masquerade[0].Source = "198.51.100.0/24"
	natChange := submit(t, e, 1, unmatched)
	probeMasqueradePacket(t, adapter, 0, 45679, false)
	// Rule updates do not rewrite an established conntrack mapping.
	probeMasqueradePacket(t, adapter, sourcePort, 45678, true)
	if _, err := e.Rollback(natChange.ID, "test"); err != nil {
		t.Fatal(err)
	}
	probeMasqueradePacket(t, adapter, 0, 45680, true)
	remove := submit(t, e, 1, EmptyConfig())
	if _, err := e.Rollback(remove.ID, "test"); err != nil {
		t.Fatal(err)
	}
	v, err = e.View(context.Background())
	if err != nil || v.Drift || !Equal(v.Observed, c) {
		t.Fatalf("native rollback: %+v %v", v, err)
	}
}
