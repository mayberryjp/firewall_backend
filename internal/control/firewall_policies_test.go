package control

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func hostPolicyConfig() Config {
	c := EmptyConfig()
	c.Interfaces = []Interface{{Name: "lan", Kind: "dummy", MTU: 1500, Up: true}}
	c.Firewall.Policy = "drop"
	c.Firewall.Policies = &FirewallPolicies{
		Hosts: []FirewallHost{
			{ID: "workstation", Name: "Workstation", Addresses: []string{"192.0.2.10", "2001:db8::10"}, Policy: "drop",
				Rules: []HostPolicyRule{{DestinationHost: "server", Protocol: "tcp", DestinationPorts: []int{443, 8443}, Action: "accept"}}},
			{ID: "server", Name: "Server", Addresses: []string{"192.0.2.20", "2001:db8::20"}, Policy: "drop"},
		},
		Interfaces: []InterfacePolicy{{Interface: "lan", Rules: []HostPolicyRule{
			{Destination: "198.51.100.0/24", Protocol: "tcp", DestinationPorts: []int{443}, Action: "drop"},
			{DestinationHost: "server", Protocol: "udp", DestinationPorts: []int{53}, Action: "accept"},
		}}},
	}
	c.Normalize()
	return c
}

type policyPacket struct {
	source, destination, ingress, protocol string
	port                                   int
	established                            bool
}

func compiledDecision(t *testing.T, c Config, packet policyPacket) string {
	t.Helper()
	rules, err := compileFirewallPolicies(c.Firewall.Policies)
	if err != nil {
		t.Fatal(err)
	}
	matchAddress := func(prefix, addr string) bool {
		return prefix == "" || netip.MustParsePrefix(prefix).Contains(netip.MustParseAddr(addr))
	}
	for _, rule := range rules {
		if rule.EstablishedRelated {
			if packet.established {
				return rule.Action
			}
			continue
		}
		if (rule.InInterface == "" || rule.InInterface == packet.ingress) &&
			matchAddress(rule.Source, packet.source) && matchAddress(rule.Destination, packet.destination) &&
			(rule.Protocol == "" || rule.Protocol == packet.protocol) &&
			(rule.DestinationPort == 0 || rule.DestinationPort == packet.port) {
			return rule.Action
		}
	}
	return c.Firewall.Policy
}

func TestHostPolicyPrecedenceAndStatefulBehavior(t *testing.T) {
	c := hostPolicyConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	// This host otherwise allows everything, so an ingress drop must override it.
	for i := range c.Firewall.Policies.Hosts {
		if c.Firewall.Policies.Hosts[i].ID == "workstation" {
			c.Firewall.Policies.Hosts[i].Policy = "accept"
		}
	}
	tests := []struct {
		name   string
		packet policyPacket
		action string
	}{
		{"interface drop overrides host accept", policyPacket{"192.0.2.10", "198.51.100.5", "lan", "tcp", 443, false}, "drop"},
		{"interface accept overrides host drop", policyPacket{"192.0.2.20", "192.0.2.20", "lan", "udp", 53, false}, "accept"},
		{"unmatched interface falls through", policyPacket{"192.0.2.10", "192.0.2.20", "lan", "tcp", 8443, false}, "accept"},
		{"source host only, destination default drop ignored", policyPacket{"192.0.2.10", "192.0.2.20", "other", "tcp", 443, false}, "accept"},
		{"source server default drop", policyPacket{"192.0.2.20", "192.0.2.10", "other", "tcp", 443, false}, "drop"},
		{"unknown source global drop", policyPacket{"192.0.2.99", "192.0.2.20", "other", "tcp", 443, false}, "drop"},
		{"unknown source interface accept", policyPacket{"192.0.2.99", "192.0.2.20", "lan", "udp", 53, false}, "accept"},
		{"established traffic bypasses new interface block", policyPacket{"192.0.2.10", "198.51.100.5", "lan", "tcp", 443, true}, "accept"},
		{"established return bypasses destination host default", policyPacket{"192.0.2.20", "192.0.2.10", "other", "tcp", 50000, true}, "accept"},
		{"ipv6 destination reference", policyPacket{"2001:db8::10", "2001:db8::20", "other", "tcp", 443, false}, "accept"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compiledDecision(t, c, test.packet); got != test.action {
				t.Fatalf("got %s, want %s", got, test.action)
			}
		})
	}
}

func TestHostPolicyPortsFamiliesAndOrdering(t *testing.T) {
	c := hostPolicyConfig()
	for _, packet := range []policyPacket{
		{"192.0.2.10", "192.0.2.20", "other", "udp", 443, false},
		{"192.0.2.10", "192.0.2.20", "other", "tcp", 80, false},
		{"192.0.2.11", "192.0.2.20", "other", "tcp", 443, false},
		{"2001:db8::10", "2001:db8::21", "other", "tcp", 443, false},
	} {
		if got := compiledDecision(t, c, packet); got != "drop" {
			t.Fatalf("unmatched traffic accepted: %+v", packet)
		}
	}
	p := c.Firewall.Policies
	p.Interfaces[0].Rules = append([]HostPolicyRule{{Protocol: "tcp", DestinationPorts: []int{443}, Action: "accept"}}, p.Interfaces[0].Rules...)
	if got := compiledDecision(t, c, policyPacket{"192.0.2.10", "198.51.100.5", "lan", "tcp", 443, false}); got != "accept" {
		t.Fatal("interface rule order lost")
	}
	other := Clone(c)
	other.Firewall.Policies.Interfaces[0].Rules[0], other.Firewall.Policies.Interfaces[0].Rules[1] =
		other.Firewall.Policies.Interfaces[0].Rules[1], other.Firewall.Policies.Interfaces[0].Rules[0]
	if Equal(c, other) {
		t.Fatal("normalization reordered interface rules")
	}
	other = Clone(c)
	other.Firewall.Policies.Hosts[0], other.Firewall.Policies.Hosts[1] = other.Firewall.Policies.Hosts[1], other.Firewall.Policies.Hosts[0]
	if !Equal(c, other) {
		t.Fatal("host inventory order changed policy meaning")
	}
}

func TestHostRuleOrderingAndAddressReferences(t *testing.T) {
	c := hostPolicyConfig()
	var source, destination *FirewallHost
	for i := range c.Firewall.Policies.Hosts {
		host := &c.Firewall.Policies.Hosts[i]
		if host.ID == "workstation" {
			source = host
		} else {
			destination = host
		}
	}
	packet := policyPacket{"192.0.2.10", "192.0.2.20", "other", "tcp", 443, false}
	source.Rules = append([]HostPolicyRule{{Protocol: "tcp", DestinationPorts: []int{443}, Action: "drop"}}, source.Rules...)
	if compiledDecision(t, c, packet) != "drop" {
		t.Fatal("first matching host rule did not win")
	}
	source.Rules[0], source.Rules[1] = source.Rules[1], source.Rules[0]
	if compiledDecision(t, c, packet) != "accept" {
		t.Fatal("host rule ordering was ignored")
	}
	destination.Addresses = []string{"192.0.2.30", "2001:db8::30"}
	packet.port = 8443
	if compiledDecision(t, c, packet) != "drop" {
		t.Fatal("destination-host reference retained a removed address")
	}
	packet.destination = "192.0.2.30"
	for _, ingress := range []string{"lan", "wan"} {
		packet.ingress = ingress
		if compiledDecision(t, c, packet) != "accept" {
			t.Fatal("host policy depended on its ingress interface")
		}
	}
	packet.source, packet.destination = "2001:db8::10", "2001:db8::30"
	if compiledDecision(t, c, packet) != "accept" {
		t.Fatal("IPv6 host reference not updated")
	}
}

func TestHostPolicyValidation(t *testing.T) {
	tests := map[string]func(*FirewallPolicies){
		"duplicate ID":         func(p *FirewallPolicies) { p.Hosts[1].ID = p.Hosts[0].ID },
		"duplicate name":       func(p *FirewallPolicies) { p.Hosts[1].Name = p.Hosts[0].Name },
		"invalid ID":           func(p *FirewallPolicies) { p.Hosts[0].ID = "../host" },
		"invalid name":         func(p *FirewallPolicies) { p.Hosts[0].Name = " host" },
		"duplicate address":    func(p *FirewallPolicies) { p.Hosts[1].Addresses[0] = p.Hosts[0].Addresses[0] },
		"prefix not address":   func(p *FirewallPolicies) { p.Hosts[0].Addresses[0] = "192.0.2.0/24" },
		"mapped IPv6":          func(p *FirewallPolicies) { p.Hosts[0].Addresses[0] = "::ffff:192.0.2.1" },
		"noncanonical IPv6":    func(p *FirewallPolicies) { p.Hosts[0].Addresses[0] = "2001:0db8::1" },
		"loopback":             func(p *FirewallPolicies) { p.Hosts[0].Addresses[0] = "127.0.0.1" },
		"no address":           func(p *FirewallPolicies) { p.Hosts[0].Addresses = nil },
		"invalid host default": func(p *FirewallPolicies) { p.Hosts[0].Policy = "reject" },
		"unknown destination": func(p *FirewallPolicies) {
			p.Interfaces[0].Rules[0].DestinationHost = "missing"
			p.Interfaces[0].Rules[0].Destination = ""
		},
		"two destinations":       func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].DestinationHost = "server" },
		"noncanonical prefix":    func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].Destination = "198.51.100.1/24" },
		"ports without protocol": func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].Protocol = "" },
		"bad protocol":           func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].Protocol = "icmp" },
		"bad action":             func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].Action = "reject" },
		"zero port":              func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].DestinationPorts = []int{0} },
		"oversize port":          func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].DestinationPorts = []int{65536} },
		"duplicate port":         func(p *FirewallPolicies) { p.Interfaces[0].Rules[0].DestinationPorts = []int{443, 443} },
		"duplicate interface":    func(p *FirewallPolicies) { p.Interfaces = append(p.Interfaces, p.Interfaces[0]) },
		"invalid interface":      func(p *FirewallPolicies) { p.Interfaces[0].Interface = "lo" },
		"unreachable family": func(p *FirewallPolicies) {
			p.Hosts[0].Rules = []HostPolicyRule{{Destination: "198.51.100.0/24", Action: "accept"}}
			p.Hosts[0].Addresses = []string{"2001:db8::10"}
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c := hostPolicyConfig()
			change(c.Firewall.Policies)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid host policy accepted")
			}
		})
	}
	c := hostPolicyConfig()
	c.Firewall.Rules = []FirewallRule{{Action: "accept"}}
	if err := c.Validate(); err == nil {
		t.Fatal("mixed legacy and policy configuration accepted")
	}
	c = hostPolicyConfig()
	c.Firewall.Policies.Interfaces[0].Interface = "missing"
	sim := NewSimulator(EmptyConfig())
	if err := sim.Preflight(context.Background(), c); err == nil {
		t.Fatal("unknown ingress interface accepted")
	}
	if err := validateFirewallInterfaces(c, []string{"missing"}); err != nil {
		t.Fatalf("adopted ingress rejected: %v", err)
	}
}

func TestPolicyExpansionLimitAndLegacyShape(t *testing.T) {
	p := &FirewallPolicies{Hosts: []FirewallHost{{ID: "host", Name: "Host", Policy: "drop"}}}
	for i := 1; i <= 16; i++ {
		p.Hosts[0].Addresses = append(p.Hosts[0].Addresses, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String())
	}
	for range 9 {
		r := HostPolicyRule{Protocol: "tcp", Action: "accept"}
		for port := 1; port <= 32; port++ {
			r.DestinationPorts = append(r.DestinationPorts, port)
		}
		p.Hosts[0].Rules = append(p.Hosts[0].Rules, r)
	}
	if _, err := compileFirewallPolicies(p); err == nil || !strings.Contains(err.Error(), "expand beyond") {
		t.Fatalf("expansion not bounded: %v", err)
	}
	c := EmptyConfig()
	data, err := json.Marshal(c.Firewall)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "policies") {
		t.Fatal("legacy JSON shape changed")
	}
}
