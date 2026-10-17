package control

import (
	"encoding/json"
	"testing"
)

func TestAllowAllICMPDefaultAndRoundTrip(t *testing.T) {
	for _, value := range []string{"", `,"allow_all_icmp":null`, `,"allow_all_icmp":true`, `,"allow_all_icmp":false`} {
		t.Run(value, func(t *testing.T) {
			var c Config
			if err := json.Unmarshal([]byte(`{"firewall":{"policy":"drop"`+value+`}}`), &c); err != nil {
				t.Fatal(err)
			}
			want := value != `,"allow_all_icmp":false`
			if c.Firewall.allowsAllICMP() != want {
				t.Fatal("incorrect default before normalization")
			}
			c.Normalize()
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			copy := Clone(c)
			if copy.Firewall.AllowAllICMP == nil || *copy.Firewall.AllowAllICMP != want || !Equal(c, copy) {
				t.Fatal("ICMP setting lost during normalization or cloning")
			}
			other := !want
			copy.Firewall.AllowAllICMP = &other
			if Equal(c, copy) {
				t.Fatal("ICMP setting ignored by configuration equality")
			}
		})
	}
	for _, value := range []string{`"true"`, `1`, `{}`} {
		var c Config
		if err := json.Unmarshal([]byte(`{"firewall":{"allow_all_icmp":`+value+`}}`), &c); err == nil {
			t.Fatalf("invalid ICMP setting %s accepted", value)
		}
	}
	if !EmptyConfig().Firewall.allowsAllICMP() {
		t.Fatal("empty configuration must allow ICMP by default")
	}
}

func TestValidationRejectsUnsupportedAndAmbiguousConfigurations(t *testing.T) {
	cases := map[string]func(*Config){
		"duplicate-interface":     func(c *Config) { c.Interfaces = append(c.Interfaces, c.Interfaces[0]) },
		"loopback":                func(c *Config) { c.Interfaces[0].Name = "lo" },
		"unsupported-kind":        func(c *Config) { c.Interfaces[0].Kind = "vlan" },
		"invalid-mtu":             func(c *Config) { c.Interfaces[0].MTU = 0 },
		"noncanonical-network":    func(c *Config) { c.Routes[0].Destination = "192.0.2.1/24" },
		"missing-interface":       func(c *Config) { c.Routes[0].Interface = "unknown" },
		"reserved-table":          func(c *Config) { c.Routes[0].Table = 254 },
		"gateway-family":          func(c *Config) { c.Routes[0].Gateway = "2001:db8::1" },
		"link-local-address":      func(c *Config) { c.Interfaces[0].Addresses = []string{"fe80::1/64"} },
		"duplicate-route":         func(c *Config) { c.Routes = append(c.Routes, c.Routes[0]) },
		"duplicate-rule":          func(c *Config) { c.Rules = append(c.Rules, c.Rules[0]) },
		"invalid-policy":          func(c *Config) { c.Firewall.Policy = "reject" },
		"mixed-firewall-families": func(c *Config) { c.Firewall.Rules[0].Destination = "2001:db8::/32" },
		"wireguard-required":      func(c *Config) { c.Interfaces[0].Kind = "wireguard" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := candidate()
			change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
	if err := candidate().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizationDoesNotReorderFirewall(t *testing.T) {
	a := candidate()
	a.Firewall.Rules = append(a.Firewall.Rules, FirewallRule{Action: "drop"})
	b := Clone(a)
	b.Firewall.Rules[0], b.Firewall.Rules[1] = b.Firewall.Rules[1], b.Firewall.Rules[0]
	if Equal(a, b) {
		t.Fatal("firewall rule order is semantically significant")
	}
}
