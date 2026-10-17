package control

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type DHCPRelayConfig struct {
	Enabled bool     `json:"enabled"`
	Servers []string `json:"servers"`
}

type DHCPRelayStatus struct {
	Interface string     `json:"interface"`
	State     string     `json:"state"`
	PID       int        `json:"pid,omitempty"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type dhcpRelayBinding struct {
	Interface string
	Address   string
	Servers   []string
}

func validateDHCPRelay(link Interface) error {
	seen := map[string]bool{}
	for _, server := range link.DHCPRelay.Servers {
		ip, err := netip.ParseAddr(server)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.String() != server || seen[server] {
			return fmt.Errorf("interface %s: DHCP relay servers must be unique canonical unicast IPv4 addresses", link.Name)
		}
		seen[server] = true
	}
	if !link.DHCPRelay.Enabled {
		return nil
	}
	if len(link.DHCPRelay.Servers) == 0 {
		return fmt.Errorf("interface %s: enabled DHCP relay requires at least one server", link.Name)
	}
	if !link.Up || (link.Kind != "dummy" && link.Kind != "vlan") {
		return fmt.Errorf("interface %s: enabled DHCP relay requires an up dummy or VLAN interface", link.Name)
	}
	if _, err := dhcpRelayAddress(link); err != nil {
		return err
	}
	return nil
}

func dhcpRelayAddress(link Interface) (string, error) {
	addresses := slices.Clone(link.Addresses)
	slices.Sort(addresses)
	for _, value := range addresses {
		prefix, err := canonicalPrefix(value, false)
		if err != nil {
			return "", err
		}
		if prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
			return prefix.Addr().String(), nil
		}
	}
	return "", fmt.Errorf("interface %s: enabled DHCP relay requires a configured unicast IPv4 address", link.Name)
}

func dhcpRelayBindings(interfaces []Interface) ([]dhcpRelayBinding, error) {
	result := []dhcpRelayBinding{}
	for _, link := range interfaces {
		if err := validateDHCPRelay(link); err != nil {
			return nil, err
		}
		if !link.DHCPRelay.Enabled {
			continue
		}
		address, err := dhcpRelayAddress(link)
		if err != nil {
			return nil, err
		}
		servers := slices.Clone(link.DHCPRelay.Servers)
		slices.Sort(servers)
		result = append(result, dhcpRelayBinding{Interface: link.Name, Address: address, Servers: servers})
	}
	slices.SortFunc(result, func(a, b dhcpRelayBinding) int {
		return strings.Compare(a.Interface, b.Interface)
	})
	addresses := map[string]bool{}
	for _, binding := range result {
		if addresses[binding.Address] {
			return nil, fmt.Errorf("DHCP relay interfaces must have distinct relay IPv4 addresses")
		}
		addresses[binding.Address] = true
	}
	return result, nil
}

func dhcpRelayArgs(bindings []dhcpRelayBinding, pidfile string) []string {
	args := []string{"--keep-in-foreground", "--conf-file=/dev/null", "--port=0",
		"--no-hosts", "--no-resolv", "--log-facility=-", "--pid-file=" + pidfile}
	for _, binding := range bindings {
		args = append(args, "--interface="+binding.Interface)
		for _, server := range binding.Servers {
			args = append(args, "--dhcp-relay="+binding.Address+","+server)
		}
	}
	return args
}

func dhcpRelayStatuses(interfaces []Interface, enabledState, unavailable string) []DHCPRelayStatus {
	result := make([]DHCPRelayStatus, 0, len(interfaces))
	for _, link := range interfaces {
		status := DHCPRelayStatus{Interface: link.Name, State: "disabled"}
		if link.DHCPRelay.Enabled {
			status.State, status.Error = enabledState, unavailable
		}
		result = append(result, status)
	}
	return result
}
