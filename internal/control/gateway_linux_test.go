package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestLinuxGatewayMonitoringRequiresOptIn(t *testing.T) {
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
	_, err = e.Submit(context.Background(), "test", Request{Config: gatewayConfig(), ConfirmSeconds: 30})
	if !errors.Is(err, ErrValidation) || len(e.Snapshot().Transactions) != 0 {
		t.Fatalf("operator gate bypassed: %v", err)
	}
}

func TestLinuxGatewayMonitoringDualStack(t *testing.T) {
	setup, namespace := relayTestNamespace(t)
	peer, _ := relayTestNamespace(t)
	relayTestVeth(t, setup, peer, "probe-parent", "probe-peer", "peer.100", 100, []string{"192.0.2.1/24", "2001:db8::1/64"})
	options := LinuxOptions{ParentInterfaces: []string{"probe-parent"}, AllowGatewayMonitoring: true, Logger: testLogger()}
	adapter, err := NewLinuxAdapter(namespace, "", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if adapter != nil {
			if err := adapter.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	store := testStore(t)
	e := testEngine(t, store, adapter)
	c := EmptyConfig()
	c.Interfaces = []Interface{{Name: "wan0", Kind: "vlan", Role: "wan", MTU: 1500, Up: true,
		Addresses: []string{"192.0.2.2/24", "2001:db8::2/64"}, VLAN: &VLAN{Parent: "probe-parent", ID: 100}}}
	c.Routes = []Route{
		{Destination: "192.0.2.1/32", Interface: "wan0", Table: 10000, Metric: 100},
		{Destination: "2001:db8::1/128", Interface: "wan0", Table: 10001, Metric: 100},
	}
	c.Rules = []Rule{{Source: "192.0.2.2/32", Table: 10000, Priority: 10000}, {Source: "2001:db8::2/128", Table: 10001, Priority: 10001}}
	m4 := smallGatewayMonitor()
	m4.Name, m4.Target, m4.Gateway = "v4", "192.0.2.1", "192.0.2.1"
	m6 := m4
	m6.Name, m6.Target, m6.Gateway, m6.SourceAddress, m6.RoutingTable = "v6", "2001:db8::1", "2001:db8::1", "2001:db8::2", 10001
	c.GatewayMonitors = []GatewayMonitor{m4, m6}
	c.Normalize()
	tx := submit(t, e, 0, c)
	waitHealth := func(name, health string) {
		t.Helper()
		until := time.Now().Add(10 * time.Second)
		var last NetworkStatistics
		for time.Now().Before(until) {
			last, err = e.Statistics(context.Background(), StatisticsQuery{Section: StatisticsGateways, Monitor: name})
			if err != nil {
				t.Fatal(err)
			}
			if len(last.Gateways) == 1 && last.Gateways[0].Health == health {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("monitor %s never became %s: %+v", name, health, last)
	}
	waitHealth("v4", "up")
	waitHealth("v6", "up")
	for _, name := range []string{"v4", "v6"} {
		stats, err := e.Statistics(context.Background(), StatisticsQuery{Section: StatisticsGateways, Monitor: name})
		if err != nil || stats.Gateways[0].Received < 2 || stats.Gateways[0].RTTVariationMS == nil || stats.Gateways[0].RTTP95MS == nil {
			t.Fatalf("real ICMP metrics missing: %+v %v", stats, err)
		}
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	var foreign netlink.Route
	var policy *netlink.Rule
	err = adapter.(*linuxAdapter).inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		link, err := h.LinkByName("wan0")
		if err != nil {
			return err
		}
		_, destination, err := net.ParseCIDR("192.0.2.1/32")
		if err != nil {
			return err
		}
		foreign = netlink.Route{Dst: destination, LinkIndex: link.Attrs().Index, Table: 19999, Scope: netlink.SCOPE_LINK}
		if err := h.RouteAdd(&foreign); err != nil {
			return err
		}
		policy = netlink.NewRule()
		policy.Family, policy.Priority, policy.Table = netlink.FAMILY_V4, 9999, 19999
		_, policy.Src, err = net.ParseCIDR("192.0.2.2/32")
		if err != nil {
			return err
		}
		return h.RuleAdd(policy)
	})
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(5 * time.Second)
	detected := false
	for time.Now().Before(until) {
		stats, err := e.Statistics(context.Background(), StatisticsQuery{Section: StatisticsGateways, Monitor: "v4"})
		if err != nil {
			t.Fatal(err)
		}
		if s := stats.Gateways[0]; s.ProcessState == "exited" && s.Health == "unknown" && strings.Contains(s.Error, "effective monitor route") {
			detected = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !detected {
		t.Fatal("probe continued on an unexpected policy-routing table")
	}
	err = adapter.(*linuxAdapter).inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		if err := h.RuleDel(policy); err != nil {
			return err
		}
		return h.RouteDel(&foreign)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReconcileServices(context.Background(), "test", nil); err != nil {
		t.Fatal(err)
	}
	waitHealth("v4", "up")
	err = adapter.(*linuxAdapter).inNamespace(context.Background(), func() error {
		wrong := m4
		wrong.Gateway = "192.0.2.254"
		session, err := openNativeGatewaySession(context.Background(), wrong)
		if err == nil {
			return errors.Join(fmt.Errorf("wrong gateway accepted"), session.Close())
		}
		if !strings.Contains(err.Error(), "effective monitor route") {
			return fmt.Errorf("unexpected gateway rejection: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = peer.inNamespace(context.Background(), func() error {
		return os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("1\n"), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	waitHealth("v4", "down")
	waitHealth("v6", "up")
	err = peer.inNamespace(context.Background(), func() error {
		return os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("0\n"), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	waitHealth("v4", "up")
	if !Equal(e.Snapshot().Desired, c) {
		t.Fatal("health monitoring changed network configuration")
	}
	disabled := Clone(c)
	disabled.GatewayMonitors[0].Enabled = false
	tx = submit(t, e, 1, disabled)
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	adapter = nil
	adapter, err = NewLinuxAdapter(namespace, "", options)
	if err != nil {
		t.Fatal(err)
	}
	e = testEngine(t, store, adapter)
	stats, err := e.Statistics(context.Background(), StatisticsQuery{Section: StatisticsGateways, Monitor: "v4"})
	if err != nil || stats.Gateways[0].ProcessState != "disabled" {
		t.Fatalf("pending restart ignored candidate: %+v %v", stats, err)
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	waitHealth("v4", "up")
}
