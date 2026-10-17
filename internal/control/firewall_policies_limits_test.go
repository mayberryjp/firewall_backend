package control

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestPolicyExpansionExactBoundary(t *testing.T) {
	p := &FirewallPolicies{}
	for i := range 2 {
		host := FirewallHost{ID: fmt.Sprintf("host%d", i), Name: fmt.Sprintf("Host %d", i),
			Addresses: []string{fmt.Sprintf("192.0.2.%d", i+1)}, Policy: "drop"}
		for j := range 64 {
			rule := HostPolicyRule{Protocol: "tcp", Action: "accept"}
			count := 32
			if i == 1 && j == 63 {
				count = 29
			}
			for port := 1; port <= count; port++ {
				rule.DestinationPorts = append(rule.DestinationPorts, port)
			}
			host.Rules = append(host.Rules, rule)
		}
		p.Hosts = append(p.Hosts, host)
	}
	rules, err := compileFirewallPolicies(p)
	if err != nil || len(rules) != maxCompiledFirewallRules {
		t.Fatalf("exact 4096-rule boundary: %d rules, %v", len(rules), err)
	}
	p.Hosts[1].Rules[63].DestinationPorts = append(p.Hosts[1].Rules[63].DestinationPorts, 30)
	if _, err := compileFirewallPolicies(p); err == nil || !strings.Contains(err.Error(), "expand beyond") {
		t.Fatalf("4097-rule expansion accepted: %v", err)
	}
}

func TestPolicyPortBoundaries(t *testing.T) {
	c := hostPolicyConfig()
	c.Firewall.Policies.Interfaces[0].Rules[0].DestinationPorts = []int{1, 65535}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid port boundaries: %v", err)
	}
	rule := &c.Firewall.Policies.Interfaces[0].Rules[0]
	rule.DestinationPorts = nil
	for port := 1; port <= 32; port++ {
		rule.DestinationPorts = append(rule.DestinationPorts, port)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("32 ports rejected: %v", err)
	}
	rule.DestinationPorts = append(rule.DestinationPorts, 33)
	if err := c.Validate(); err == nil {
		t.Fatal("33 ports accepted")
	}
}

func TestPolicyInventoryAndMetadataLimits(t *testing.T) {
	p := &FirewallPolicies{}
	for i := range 128 {
		p.Hosts = append(p.Hosts, FirewallHost{ID: fmt.Sprintf("host%d", i), Name: fmt.Sprintf("Host %d", i),
			Addresses: []string{fmt.Sprintf("192.0.2.%d", i+1)}, Policy: "drop"})
	}
	for i := range 32 {
		p.Interfaces = append(p.Interfaces, InterfacePolicy{Interface: fmt.Sprintf("lan%d", i)})
	}
	if _, err := compileFirewallPolicies(p); err != nil {
		t.Fatalf("maximum inventory rejected: %v", err)
	}
	p.Interfaces = append(p.Interfaces, InterfacePolicy{Interface: "lan32"})
	if _, err := compileFirewallPolicies(p); err == nil {
		t.Fatal("33 interface policies accepted")
	}
	p.Interfaces = p.Interfaces[:32]
	p.Hosts = append(p.Hosts, FirewallHost{ID: "extra", Name: "Extra", Addresses: []string{"192.0.2.200"}, Policy: "drop"})
	if _, err := compileFirewallPolicies(p); err == nil {
		t.Fatal("129 hosts accepted")
	}
	p.Hosts = p.Hosts[:128]
	for i := range p.Hosts {
		for range 64 {
			p.Hosts[i].Rules = append(p.Hosts[i].Rules, HostPolicyRule{Action: "accept"})
		}
	}
	if err := p.validate(); err == nil || !strings.Contains(err.Error(), "metadata exceeds") {
		t.Fatalf("oversized metadata accepted: %v", err)
	}
}

func TestHostPolicyPersistenceAndHistoricalRestore(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	config := hostPolicyConfig()
	tx := submit(t, e, 0, config)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	restarted := testEngine(t, store, NewSimulator(persisted.Desired))
	view, err := restarted.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Desired, config) || !Equal(view.Observed, config) {
		t.Fatalf("restart lost host policies: %+v %v", view, err)
	}
	restore, err := restarted.Restore(context.Background(), "test", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Confirm(context.Background(), restore.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if restarted.Snapshot().Desired.Firewall.Policies != nil {
		t.Fatal("legacy restoration retained host mode")
	}
	restore, err = restarted.Restore(context.Background(), "test", 1, RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Confirm(context.Background(), restore.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if !Equal(restarted.Snapshot().Desired, config) {
		t.Fatal("historical restore lost host inventory or policies")
	}
}
