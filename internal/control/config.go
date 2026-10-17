package control

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

type Config struct {
	Interfaces []Interface       `json:"interfaces"`
	Routes     []Route           `json:"routes"`
	Rules      []Rule            `json:"policy_rules"`
	Firewall   Firewall          `json:"firewall"`
	Softflowd  []SoftflowdConfig `json:"softflowd"`
	Kernel     KernelConfig      `json:"kernel"`
}

type Interface struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	MTU       int        `json:"mtu"`
	Up        bool       `json:"up"`
	Addresses []string   `json:"addresses"`
	WireGuard *WireGuard `json:"wireguard,omitempty"`
	VLAN      *VLAN      `json:"vlan,omitempty"`
}

type WireGuard struct {
	KeyRef     string `json:"key_ref"`
	ListenPort int    `json:"listen_port"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips"`
	Keepalive  int      `json:"persistent_keepalive_seconds"`
}

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface"`
	Table       int    `json:"table"`
	Metric      int    `json:"metric"`
}

type Rule struct {
	Priority int    `json:"priority"`
	Source   string `json:"source"`
	Table    int    `json:"table"`
}

// Firewall owns only the inet/netcontrol table.
type Firewall struct {
	Policy   string            `json:"policy"`
	Rules    []FirewallRule    `json:"rules"`
	NAT      NAT               `json:"nat"`
	Policies *FirewallPolicies `json:"policies,omitempty"`
}

type NAT struct {
	Masquerade []MasqueradeRule `json:"masquerade"`
}

type MasqueradeRule struct {
	Family       string `json:"family"`
	Source       string `json:"source,omitempty"`
	OutInterface string `json:"out_interface"`
}

type FirewallRule struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Action      string `json:"action"`
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
var keyPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func EmptyConfig() Config {
	c := Config{Firewall: Firewall{Policy: "accept"}}
	c.Normalize()
	return c
}

func Clone[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var result T
	if err := json.Unmarshal(b, &result); err != nil {
		panic(err)
	}
	return result
}

func (c *Config) Normalize() {
	c.Kernel.Normalize()
	if c.Interfaces == nil {
		c.Interfaces = []Interface{}
	}
	if c.Routes == nil {
		c.Routes = []Route{}
	}
	if c.Rules == nil {
		c.Rules = []Rule{}
	}
	if c.Softflowd == nil {
		c.Softflowd = []SoftflowdConfig{}
	}
	for i := range c.Softflowd {
		if c.Softflowd[i].Timeouts == nil {
			c.Softflowd[i].Timeouts = map[string]int{}
		}
	}
	slices.SortFunc(c.Softflowd, func(a, b SoftflowdConfig) int { return strings.Compare(a.Name, b.Name) })
	if c.Firewall.Rules == nil {
		c.Firewall.Rules = []FirewallRule{}
	}
	if c.Firewall.Policies != nil {
		c.Firewall.Policies.normalize()
	}
	if c.Firewall.NAT.Masquerade == nil {
		c.Firewall.NAT.Masquerade = []MasqueradeRule{}
	}
	for i := range c.Interfaces {
		link := &c.Interfaces[i]
		if link.Addresses == nil {
			link.Addresses = []string{}
		}
		slices.Sort(link.Addresses)
		if link.WireGuard != nil {
			if link.WireGuard.Peers == nil {
				link.WireGuard.Peers = []Peer{}
			}
			for j := range link.WireGuard.Peers {
				p := &link.WireGuard.Peers[j]
				if p.AllowedIPs == nil {
					p.AllowedIPs = []string{}
				}
				slices.Sort(p.AllowedIPs)
			}
			slices.SortFunc(link.WireGuard.Peers, func(a, b Peer) int { return strings.Compare(a.PublicKey, b.PublicKey) })
		}
	}
	slices.SortFunc(c.Interfaces, func(a, b Interface) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.Routes, func(a, b Route) int { return strings.Compare(routeKey(a), routeKey(b)) })
	slices.SortFunc(c.Rules, func(a, b Rule) int { return a.Priority - b.Priority })
}

func Equal(a, b Config) bool {
	a, b = Clone(a), Clone(b)
	a.Normalize()
	b.Normalize()
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func routeKey(r Route) string { return fmt.Sprintf("%d/%s/%d", r.Table, r.Destination, r.Metric) }

func canonicalPrefix(s string, network bool) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || p.Addr().Is4In6() || (network && p != p.Masked()) || p.String() != s {
		return netip.Prefix{}, fmt.Errorf("non-canonical IP prefix %q", s)
	}
	return p, nil
}

func (c Config) Validate() error {
	if err := c.Kernel.Validate(); err != nil {
		return err
	}
	names := map[string]bool{}
	for _, link := range c.Interfaces {
		if !validInterfaceName(link.Name) || names[link.Name] {
			return fmt.Errorf("invalid or duplicate interface name %q", link.Name)
		}
		names[link.Name] = true
		if link.Kind != "dummy" && link.Kind != "wireguard" && link.Kind != "vlan" {
			return fmt.Errorf("interface %s: supported kinds are dummy, wireguard, and vlan", link.Name)
		}
		if link.MTU < 1280 || link.MTU > 65535 {
			return fmt.Errorf("interface %s: MTU must be 1280..65535", link.Name)
		}
		seen := map[string]bool{}
		for _, a := range link.Addresses {
			p, err := canonicalPrefix(a, false)
			if err != nil {
				return err
			}
			if !p.Addr().IsGlobalUnicast() || seen[a] {
				return fmt.Errorf("invalid or duplicate address %q", a)
			}
			seen[a] = true
		}
		if link.Kind == "wireguard" {
			if link.WireGuard == nil {
				return fmt.Errorf("%s: wireguard configuration required", link.Name)
			}
			w := link.WireGuard
			if !keyPattern.MatchString(w.KeyRef) || w.ListenPort < 0 || w.ListenPort > 65535 {
				return fmt.Errorf("%s: invalid WireGuard key reference or port", link.Name)
			}
			if w.ListenPort == 0 {
				return fmt.Errorf("%s: specify a stable nonzero WireGuard listen port", link.Name)
			}
			keys, allowed := map[string]bool{}, map[string]bool{}
			for _, peer := range w.Peers {
				if err := validatePublicKey(peer.PublicKey); err != nil {
					return err
				}
				if keys[peer.PublicKey] {
					return fmt.Errorf("duplicate WireGuard peer")
				}
				keys[peer.PublicKey] = true
				if peer.Endpoint != "" {
					e, err := netip.ParseAddrPort(peer.Endpoint)
					if err != nil || e.Port() == 0 || e.Addr().Zone() != "" || e.Addr().Is4In6() {
						return fmt.Errorf("endpoint must be a numeric IP:port (IPv6 in brackets)")
					}
				}
				if peer.Keepalive < 0 || peer.Keepalive > 65535 {
					return fmt.Errorf("invalid keepalive")
				}
				for _, prefix := range peer.AllowedIPs {
					if _, err := canonicalPrefix(prefix, true); err != nil {
						return err
					}
					if allowed[prefix] {
						return fmt.Errorf("duplicate WireGuard allowed IP %s", prefix)
					}
					allowed[prefix] = true
				}
			}
		} else if link.WireGuard != nil {
			return fmt.Errorf("%s: WireGuard settings require wireguard kind", link.Name)
		}
		if link.Kind == "vlan" {
			if link.VLAN == nil || !validInterfaceName(link.VLAN.Parent) || link.VLAN.ID < 1 || link.VLAN.ID > 4094 {
				return fmt.Errorf("%s: VLAN requires a valid parent and ID 1..4094", link.Name)
			}
		} else if link.VLAN != nil {
			return fmt.Errorf("%s: VLAN settings require vlan kind", link.Name)
		}
	}
	if _, err := orderedInterfaces(c.Interfaces); err != nil {
		return err
	}
	if err := validateSoftflowd(c.Softflowd); err != nil {
		return err
	}
	routeKeys := map[string]bool{}
	for _, r := range c.Routes {
		p, err := canonicalPrefix(r.Destination, true)
		if err != nil {
			return err
		}
		if !names[r.Interface] || r.Table < 10000 || r.Table > 19999 || r.Metric < 1 || r.Metric > 2147483647 {
			return fmt.Errorf("route requires managed interface, table 10000..19999, and positive 32-bit metric")
		}
		if r.Gateway != "" {
			g, err := netip.ParseAddr(r.Gateway)
			if err != nil || g.Is4In6() || g.Zone() != "" || g.Is4() != p.Addr().Is4() || g.String() != r.Gateway {
				return fmt.Errorf("invalid route gateway %q", r.Gateway)
			}
		}
		if routeKeys[routeKey(r)] {
			return fmt.Errorf("duplicate route table/destination/metric")
		}
		routeKeys[routeKey(r)] = true
	}
	priorities := map[int]bool{}
	for _, r := range c.Rules {
		if _, err := canonicalPrefix(r.Source, true); err != nil {
			return err
		}
		if r.Priority < 10000 || r.Priority > 19999 || r.Table < 10000 || r.Table > 19999 || priorities[r.Priority] {
			return fmt.Errorf("policy rules require unique priorities and tables in 10000..19999")
		}
		priorities[r.Priority] = true
	}
	if c.Firewall.Policy != "accept" && c.Firewall.Policy != "drop" {
		return fmt.Errorf("firewall policy must be accept or drop")
	}
	if c.Firewall.Policies != nil {
		if len(c.Firewall.Rules) != 0 {
			return fmt.Errorf("legacy firewall rules cannot be mixed with host/interface policies")
		}
		if _, err := compileFirewallPolicies(c.Firewall.Policies); err != nil {
			return err
		}
	}
	for _, r := range c.Firewall.Rules {
		if r.Action != "accept" && r.Action != "drop" {
			return fmt.Errorf("firewall action must be accept or drop")
		}
		var family int
		for _, prefix := range []string{r.Source, r.Destination} {
			if prefix == "" {
				continue
			}
			p, err := canonicalPrefix(prefix, true)
			if err != nil {
				return err
			}
			if family != 0 && family != p.Addr().BitLen() {
				return fmt.Errorf("firewall source and destination must use the same family")
			}
			family = p.Addr().BitLen()
		}
	}
	for _, r := range c.Firewall.NAT.Masquerade {
		if err := r.validate(names); err != nil {
			return err
		}
		hasAddress := false
		for _, link := range c.Interfaces {
			if link.Name != r.OutInterface {
				continue
			}
			for _, address := range link.Addresses {
				p, _ := netip.ParsePrefix(address)
				if p.Addr().Is4() == (r.Family == "ipv4") {
					hasAddress = true
				}
			}
		}
		if !hasAddress {
			return fmt.Errorf("masquerade egress %s requires an address of family %s", r.OutInterface, r.Family)
		}
	}
	return nil
}

func (r MasqueradeRule) validate(interfaces map[string]bool) error {
	if r.Family != "ipv4" && r.Family != "ipv6" {
		return fmt.Errorf("masquerade family must be ipv4 or ipv6")
	}
	if !validInterfaceName(r.OutInterface) ||
		(interfaces != nil && !interfaces[r.OutInterface]) {
		return fmt.Errorf("masquerade requires a managed egress interface")
	}
	if r.Source != "" {
		p, err := canonicalPrefix(r.Source, true)
		if err != nil {
			return err
		}
		if p.Addr().Is4() != (r.Family == "ipv4") {
			return fmt.Errorf("masquerade source must match its IP family")
		}
	}
	return nil
}
