package control

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
)

const maxCompiledFirewallRules = 4096
const maxFirewallPolicyMetadata = 64 << 10

type FirewallPolicies struct {
	Hosts      []FirewallHost    `json:"hosts"`
	Interfaces []InterfacePolicy `json:"interfaces"`
}

type FirewallHost struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Addresses []string         `json:"addresses"`
	Policy    string           `json:"policy"`
	Rules     []HostPolicyRule `json:"rules"`
}

type InterfacePolicy struct {
	Interface string           `json:"interface"`
	Rules     []HostPolicyRule `json:"rules"`
}

type HostPolicyRule struct {
	DestinationHost  string `json:"destination_host,omitempty"`
	Destination      string `json:"destination,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	DestinationPorts []int  `json:"destination_ports,omitempty"`
	Action           string `json:"action"`
}

type compiledFirewallRule struct {
	Source             string
	Destination        string
	InInterface        string
	Protocol           string
	DestinationPort    int
	Action             string
	EstablishedRelated bool
}

func (p *FirewallPolicies) normalize() {
	if p.Hosts == nil {
		p.Hosts = []FirewallHost{}
	}
	if p.Interfaces == nil {
		p.Interfaces = []InterfacePolicy{}
	}
	for i := range p.Hosts {
		h := &p.Hosts[i]
		if h.Addresses == nil {
			h.Addresses = []string{}
		}
		if h.Rules == nil {
			h.Rules = []HostPolicyRule{}
		}
		slices.Sort(h.Addresses)
		for j := range h.Rules {
			slices.Sort(h.Rules[j].DestinationPorts)
		}
	}
	for i := range p.Interfaces {
		if p.Interfaces[i].Rules == nil {
			p.Interfaces[i].Rules = []HostPolicyRule{}
		}
		for j := range p.Interfaces[i].Rules {
			slices.Sort(p.Interfaces[i].Rules[j].DestinationPorts)
		}
	}
	slices.SortFunc(p.Hosts, func(a, b FirewallHost) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(p.Interfaces, func(a, b InterfacePolicy) int { return strings.Compare(a.Interface, b.Interface) })
}

func firewallAction(value string) bool { return value == "accept" || value == "drop" }

func (p *FirewallPolicies) validate() error {
	if len(p.Hosts) > 128 || len(p.Interfaces) > 32 {
		return fmt.Errorf("firewall policies support at most 128 hosts and 32 ingress interfaces")
	}
	hosts, addresses, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, h := range p.Hosts {
		if !keyPattern.MatchString(h.ID) || hosts[h.ID] {
			return fmt.Errorf("invalid or duplicate firewall host ID %q", h.ID)
		}
		if h.Name == "" || len(h.Name) > 80 || strings.TrimSpace(h.Name) != h.Name || strings.ContainsFunc(h.Name, unicode.IsControl) || names[h.Name] {
			return fmt.Errorf("firewall host names must be nonempty, unique and at most 80 bytes without outer whitespace or control characters")
		}
		hosts[h.ID], names[h.Name] = true, true
		if !firewallAction(h.Policy) || len(h.Addresses) == 0 || len(h.Addresses) > 16 {
			return fmt.Errorf("host %s requires an accept/drop default and 1..16 addresses", h.ID)
		}
		for _, value := range h.Addresses {
			a, err := netip.ParseAddr(value)
			if err != nil || a.String() != value || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() || addresses[value] {
				return fmt.Errorf("host %s: addresses must be canonical, unique unicast IPs (not prefixes)", h.ID)
			}
			addresses[value] = true
		}
	}
	validateRules := func(rules []HostPolicyRule) error {
		if len(rules) > 64 {
			return fmt.Errorf("at most 64 rules per host or interface are supported")
		}
		for _, r := range rules {
			if !firewallAction(r.Action) || (r.Protocol != "" && r.Protocol != "tcp" && r.Protocol != "udp") {
				return fmt.Errorf("policy rules require accept/drop and protocol tcp, udp, or omitted (any)")
			}
			if r.DestinationHost != "" && (r.Destination != "" || !hosts[r.DestinationHost]) {
				return fmt.Errorf("destination_host must reference an existing host and cannot be combined with destination")
			}
			if r.Destination != "" {
				if _, err := canonicalPrefix(r.Destination, true); err != nil {
					return err
				}
			}
			if len(r.DestinationPorts) > 32 || (len(r.DestinationPorts) != 0 && r.Protocol == "") {
				return fmt.Errorf("destination ports require tcp/udp and at most 32 ports")
			}
			ports := map[int]bool{}
			for _, port := range r.DestinationPorts {
				if port < 1 || port > 65535 || ports[port] {
					return fmt.Errorf("destination ports must be unique integers in 1..65535")
				}
				ports[port] = true
			}
		}
		return nil
	}
	for _, h := range p.Hosts {
		if err := validateRules(h.Rules); err != nil {
			return fmt.Errorf("host %s: %w", h.ID, err)
		}
	}
	interfaces := map[string]bool{}
	for _, policy := range p.Interfaces {
		if !validInterfaceName(policy.Interface) || interfaces[policy.Interface] {
			return fmt.Errorf("invalid or duplicate ingress policy interface %q", policy.Interface)
		}
		interfaces[policy.Interface] = true
		if err := validateRules(policy.Rules); err != nil {
			return fmt.Errorf("interface %s: %w", policy.Interface, err)
		}
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(data) > maxFirewallPolicyMetadata {
		return fmt.Errorf("firewall policy metadata exceeds %d bytes", maxFirewallPolicyMetadata)
	}
	return nil
}

func hostPrefix(value string) string {
	a := netip.MustParseAddr(value)
	return netip.PrefixFrom(a, a.BitLen()).String()
}

func compileFirewallPolicies(p *FirewallPolicies) ([]compiledFirewallRule, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	hosts := map[string]FirewallHost{}
	for _, h := range p.Hosts {
		hosts[h.ID] = h
	}
	result := []compiledFirewallRule{{EstablishedRelated: true, Action: "accept"}}
	add := func(rule compiledFirewallRule) error {
		if len(result) >= maxCompiledFirewallRules {
			return fmt.Errorf("firewall policies expand beyond %d rules", maxCompiledFirewallRules)
		}
		result = append(result, rule)
		return nil
	}
	expand := func(rule HostPolicyRule, sources []string, ingress string) error {
		destinations := []string{rule.Destination}
		if rule.DestinationHost != "" {
			destinations = nil
			for _, addr := range hosts[rule.DestinationHost].Addresses {
				destinations = append(destinations, hostPrefix(addr))
			}
		}
		ports := rule.DestinationPorts
		if len(ports) == 0 {
			ports = []int{0}
		}
		before := len(result)
		for _, source := range sources {
			for _, destination := range destinations {
				if source != "" && destination != "" {
					src, _ := netip.ParsePrefix(source)
					dst, _ := netip.ParsePrefix(destination)
					if src.Addr().BitLen() != dst.Addr().BitLen() {
						continue
					}
				}
				for _, port := range ports {
					if err := add(compiledFirewallRule{Source: source, Destination: destination, InInterface: ingress,
						Protocol: rule.Protocol, DestinationPort: port, Action: rule.Action}); err != nil {
						return err
					}
				}
			}
		}
		if before == len(result) {
			return fmt.Errorf("policy destination has no address family in common with its source host")
		}
		return nil
	}
	for _, policy := range p.Interfaces {
		for _, rule := range policy.Rules {
			if err := expand(rule, []string{""}, policy.Interface); err != nil {
				return nil, err
			}
		}
	}
	for _, host := range p.Hosts {
		sources := make([]string, 0, len(host.Addresses))
		for _, address := range host.Addresses {
			sources = append(sources, hostPrefix(address))
		}
		for _, rule := range host.Rules {
			if err := expand(rule, sources, ""); err != nil {
				return nil, err
			}
		}
		for _, source := range sources {
			if err := add(compiledFirewallRule{Source: source, Action: host.Policy}); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func validateFirewallInterfaces(c Config, parents []string) error {
	if c.Firewall.Policies == nil {
		return nil
	}
	names := map[string]bool{}
	for _, link := range c.Interfaces {
		names[link.Name] = true
	}
	for _, parent := range parents {
		names[parent] = true
	}
	for _, policy := range c.Firewall.Policies.Interfaces {
		if !names[policy.Interface] {
			return fmt.Errorf("%w: ingress policy interface %s must be managed or operator-adopted", ErrValidation, policy.Interface)
		}
	}
	return nil
}
