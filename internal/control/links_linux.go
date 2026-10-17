package control

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
)

func parentInfo(link netlink.Link) ParentInterface {
	a := link.Attrs()
	return ParentInterface{Name: a.Name, Kind: link.Type(), Index: a.Index, MAC: a.HardwareAddr.String(),
		MTU: a.MTU, Up: a.Flags&net.FlagUp != 0, Available: true}
}

func (a *linuxAdapter) initializeParents(names []string) error {
	err := a.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		for _, name := range names {
			if !validInterfaceName(name) {
				return fmt.Errorf("invalid adopted parent name %q", name)
			}
			if _, exists := a.parents[name]; exists {
				return fmt.Errorf("duplicate adopted parent %s", name)
			}
			link, err := h.LinkByName(name)
			if err != nil {
				return fmt.Errorf("adopt parent %s: %w", name, err)
			}
			if (link.Type() != "device" && link.Type() != "veth" && link.Type() != "dummy") || len(link.Attrs().HardwareAddr) != 6 {
				return fmt.Errorf("parent %s must be a pre-provisioned Ethernet device, veth, or dummy", name)
			}
			a.parents[name] = parentInfo(link)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(names) != 0 {
		sorted := slices.Clone(names)
		slices.Sort(sorted)
		var identity strings.Builder
		for _, name := range sorted {
			p := a.parents[name]
			fmt.Fprintf(&identity, "%s:%d:%s:%s;", p.Name, p.Index, p.Kind, p.MAC)
		}
		a.scope += fmt.Sprintf(":parents:%x", sha256.Sum256([]byte(identity.String())))
	}
	return nil
}

func (a *linuxAdapter) checkParents(h *netlink.Handle) error {
	for name, expected := range a.parents {
		link, err := h.LinkByName(name)
		if err != nil {
			return fmt.Errorf("protected parent %s unavailable: %w", name, err)
		}
		actual := parentInfo(link)
		if actual.Index != expected.Index || actual.Kind != expected.Kind || actual.MAC != expected.MAC {
			return fmt.Errorf("protected parent %s was replaced or changed identity", name)
		}
	}
	return nil
}

func (a *linuxAdapter) preflightLinks(h *netlink.Handle, c Config) error {
	if err := a.checkParents(h); err != nil {
		return err
	}
	managed := map[string]Interface{}
	for _, link := range c.Interfaces {
		if _, protected := a.parents[link.Name]; protected {
			return fmt.Errorf("%w: adopted parent %s is read-only and cannot be configured as an owned interface", ErrValidation, link.Name)
		}
		managed[link.Name] = link
	}
	for _, link := range c.Interfaces {
		if link.VLAN == nil {
			continue
		}
		if _, owned := managed[link.VLAN.Parent]; owned {
			continue
		}
		if _, adopted := a.parents[link.VLAN.Parent]; !adopted {
			return fmt.Errorf("%w: VLAN parent %s must be managed or explicitly adopted", ErrValidation, link.VLAN.Parent)
		}
		parent, err := h.LinkByName(link.VLAN.Parent)
		if err != nil {
			return err
		}
		if link.MTU > parent.Attrs().MTU {
			return fmt.Errorf("%w: VLAN %s MTU exceeds adopted parent MTU", ErrValidation, link.Name)
		}
	}
	for _, s := range c.Softflowd {
		if _, owned := managed[s.Interface]; owned {
			continue
		}
		if _, adopted := a.parents[s.Interface]; !adopted {
			return fmt.Errorf("%w: capture interface %s must be managed or adopted", ErrValidation, s.Interface)
		}
	}
	return nil
}

func deletionOrder(links []netlink.Link) []netlink.Link {
	result := slices.Clone(links)
	byIndex := map[int]netlink.Link{}
	for _, link := range links {
		byIndex[link.Attrs().Index] = link
	}
	depth := func(link netlink.Link) int {
		for n := 0; n < len(links); n++ {
			vlan, ok := link.(*netlink.Vlan)
			if !ok {
				return n
			}
			parent, exists := byIndex[vlan.ParentIndex]
			if !exists {
				return n + 1
			}
			link = parent
		}
		return len(links)
	}
	slices.SortFunc(result, func(a, b netlink.Link) int { return depth(b) - depth(a) })
	return result
}

func (a *linuxAdapter) Runtime(ctx context.Context, hints Config) (RuntimeState, error) {
	result := RuntimeState{Parents: []ParentInterface{}, Softflowd: []SoftflowdStatus{}, DHCPRelay: []DHCPRelayStatus{}}
	err := a.inNamespace(ctx, func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		for name, expected := range a.parents {
			info := expected
			link, err := h.LinkByName(name)
			if err != nil {
				info.Available, info.Error = false, err.Error()
			} else {
				info = parentInfo(link)
				if info.Index != expected.Index || info.Kind != expected.Kind || info.MAC != expected.MAC {
					info.Available, info.Error = false, "parent identity changed"
				}
			}
			result.Parents = append(result.Parents, info)
		}
		if a.flows != nil {
			result.Softflowd = a.flows.Status(ctx, hints.Softflowd)
		} else {
			for _, s := range hints.Softflowd {
				status := SoftflowdStatus{Name: s.Name, State: "disabled"}
				if s.Enabled {
					status.State, status.Error = "unavailable", "softflowd integration is not configured"
				}
				result.Softflowd = append(result.Softflowd, status)
			}
		}
		result.DHCPRelay = dhcpRelayStatuses(hints.Interfaces, "unavailable", "DHCP relay integration is not configured")
		if a.relay != nil {
			result.DHCPRelay = a.relay.Status(hints.Interfaces)
		}
		return ctx.Err()
	})
	slices.SortFunc(result.Parents, func(a, b ParentInterface) int { return strings.Compare(a.Name, b.Name) })
	return result, err
}

func (a *linuxAdapter) Resume(ctx context.Context, c Config) error {
	if a.flows == nil {
		for _, s := range c.Softflowd {
			if s.Enabled {
				return fmt.Errorf("softflowd integration is not configured")
			}
		}
	}
	return a.inNamespace(ctx, func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		if err := a.preflightLinks(h, c); err != nil {
			return err
		}
		if err := a.preflightDHCPRelay(ctx, c.Interfaces); err != nil {
			return err
		}
		if a.flows != nil {
			if err := a.flows.Preflight(ctx, c.Softflowd); err != nil {
				return err
			}
			if err := a.flows.Reconcile(ctx, c.Softflowd); err != nil {
				return err
			}
		}
		if a.relay != nil {
			return a.relay.Reconcile(ctx, c.Interfaces)
		}
		return ctx.Err()
	})
}

func (a *linuxAdapter) preflightDHCPRelay(ctx context.Context, interfaces []Interface) error {
	if a.relay != nil {
		return a.relay.Preflight(ctx, interfaces)
	}
	for _, link := range interfaces {
		if link.DHCPRelay.Enabled {
			return fmt.Errorf("%w: DHCP relay integration is not configured", ErrValidation)
		}
	}
	return ctx.Err()
}

func (a *linuxAdapter) observeDHCPRelay(interfaces []Interface) {
	if a.relay != nil {
		a.relay.Observe(interfaces)
		return
	}
	for i := range interfaces {
		interfaces[i].DHCPRelay.Enabled = false
	}
}

func (a *linuxAdapter) observeServices(ctx context.Context, hints []SoftflowdConfig) []SoftflowdConfig {
	if a.flows != nil {
		return a.flows.Observe(ctx, hints)
	}
	result := Clone(hints)
	for i := range result {
		result[i].Enabled = false
	}
	return result
}
