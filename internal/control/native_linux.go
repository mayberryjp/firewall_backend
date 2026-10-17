package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
	rtnetlink "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const ownedProtocol = 242

type linuxAdapter struct {
	namespace        netns.NsHandle
	scope            string
	keys             string
	parents          map[string]ParentInterface
	flows            *softflowdManager
	relay            *dhcpRelayManager
	hostNamespace    netns.NsHandle
	hostTunablesLock *flock.Flock
}

func NewLinuxAdapter(namespace, keyDirectory string, options ...LinuxOptions) (Adapter, error) {
	if len(options) > 1 {
		return nil, fmt.Errorf("at most one Linux options object is supported")
	}
	var option LinuxOptions
	if len(options) == 1 {
		option = options[0]
	}
	if !keyPattern.MatchString(namespace) {
		return nil, fmt.Errorf("an explicit named network namespace is required")
	}
	handle, err := netns.GetFromName(namespace)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(handle), &stat); err != nil {
		handle.Close()
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		handle.Close()
		return nil, err
	}
	a := &linuxAdapter{namespace: handle, keys: keyDirectory, parents: map[string]ParentInterface{}, scope: fmt.Sprintf("linux:%s:%d:%d", strings.TrimSpace(string(boot)), stat.Dev, stat.Ino)}
	if err := a.initializeParents(option.ParentInterfaces); err != nil {
		handle.Close()
		return nil, err
	}
	if option.AllowHostTunables {
		if err := a.initializeHostTunables(); err != nil {
			return nil, errors.Join(err, a.Close())
		}
	}
	if option.SoftflowdBinary != "" {
		a.flows, err = newSoftflowdManager(a, option)
		if err != nil {
			return nil, errors.Join(err, a.Close())
		}
		if option.DHCPRelayBinary != "" {
			a.relay, err = newDHCPRelayManager(a, option)
			if err != nil {
				return nil, errors.Join(err, a.Close())
			}
		}
	}
	return a, nil
}

func (a *linuxAdapter) Scope() string { return a.scope }
func (a *linuxAdapter) Close() error {
	var err error
	if a.flows != nil {
		err = a.flows.Close()
	}
	if a.relay != nil {
		err = errors.Join(err, a.relay.Close())
	}
	if a.hostTunablesLock != nil {
		err = errors.Join(err, a.hostNamespace.Close(), a.hostTunablesLock.Unlock())
		a.hostTunablesLock = nil
	}
	return errors.Join(err, a.namespace.Close())
}

// Each operation uses a pinned thread. The HTTP listener remains outside the
// managed namespace, so a migration cannot remove its own management interface.
func (a *linuxAdapter) inNamespace(ctx context.Context, fn func() error) error {
	return a.runInNamespace(ctx, a.namespace, true, fn)
}

func (a *linuxAdapter) runInNamespace(ctx context.Context, target netns.NsHandle, forbidHost bool, fn func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, err := netns.Get()
		if err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		defer original.Close()
		initNS, err := netns.GetFromPid(1)
		if err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		isHost := target.Equal(original) || target.Equal(initNS)
		initNS.Close()
		if forbidHost && isHost {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("refusing current or PID 1 network namespace")
			return
		}
		if err := ctx.Err(); err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		if err := netns.Set(target); err != nil {
			runtime.UnlockOSThread()
			result <- err
			return
		}
		err = fn()
		restoreErr := netns.Set(original)
		if restoreErr == nil {
			runtime.UnlockOSThread()
		}
		// Exiting a still-locked goroutine destroys its thread if restoration failed.
		result <- errors.Join(err, restoreErr)
	}()
	return <-result
}

func (a *linuxAdapter) privateKey(ref string) (wgtypes.Key, error) {
	if !keyPattern.MatchString(ref) {
		return wgtypes.Key{}, fmt.Errorf("invalid key reference")
	}
	root, err := os.OpenRoot(a.keys)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("open key directory: %w", err)
	}
	defer root.Close()
	f, err := root.Open(ref)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("open key reference %s: %w", ref, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return wgtypes.Key{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return wgtypes.Key{}, fmt.Errorf("key %s must be a private regular file (mode 0600 or stricter)", ref)
	}
	data, err := io.ReadAll(io.LimitReader(f, 128))
	if err != nil {
		return wgtypes.Key{}, err
	}
	key, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
	if err != nil || key == (wgtypes.Key{}) {
		return wgtypes.Key{}, fmt.Errorf("key reference %s contains an invalid private key", ref)
	}
	return key, nil
}

func (a *linuxAdapter) Preflight(ctx context.Context, c Config) error {
	var parents []string
	for name := range a.parents {
		parents = append(parents, name)
	}
	if err := validateFirewallInterfaces(c, parents); err != nil {
		return err
	}
	for _, link := range c.Interfaces {
		if link.WireGuard != nil {
			if _, err := a.privateKey(link.WireGuard.KeyRef); err != nil {
				return err
			}
		}
	}
	err := a.inNamespace(ctx, func() error {
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
			return a.flows.Preflight(ctx, c.Softflowd)
		}
		for _, service := range c.Softflowd {
			if service.Enabled {
				return fmt.Errorf("%w: softflowd integration is not configured by the operator", ErrValidation)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.preflightKernel(ctx, c.Kernel)
}

func (a *linuxAdapter) Observe(ctx context.Context, hints Config) (Config, error) {
	var observed Config
	// Roles are configuration metadata, not kernel link attributes.
	metadata := make(map[string]Interface, len(hints.Interfaces))
	for _, link := range hints.Interfaces {
		metadata[link.Name] = link
	}
	err := a.inNamespace(ctx, func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		links, err := h.LinkList()
		if err != nil {
			return err
		}
		byIndex := map[int]string{}
		for _, l := range links {
			byIndex[l.Attrs().Index] = l.Attrs().Name
		}
		if err := a.checkParents(h); err != nil {
			return err
		}
		for _, l := range links {
			if _, adopted := a.parents[l.Attrs().Name]; l.Attrs().Name == "lo" || adopted {
				continue
			}
			hint := metadata[l.Attrs().Name]
			link := Interface{Name: l.Attrs().Name, Kind: l.Type(), Role: hint.Role, DHCPRelay: Clone(hint.DHCPRelay),
				MTU: l.Attrs().MTU, Up: l.Attrs().Flags&net.FlagUp != 0}
			if vlan, ok := l.(*netlink.Vlan); ok {
				if vlan.VlanProtocol != netlink.VLAN_PROTOCOL_8021Q || byIndex[vlan.ParentIndex] == "" {
					return fmt.Errorf("unsupported VLAN protocol or missing parent on %s", link.Name)
				}
				link.VLAN = &VLAN{Parent: byIndex[vlan.ParentIndex], ID: vlan.VlanId}
			}
			addrs, err := h.AddrList(l, netlink.FAMILY_ALL)
			if err != nil {
				return err
			}
			for _, addr := range addrs {
				if addr.Scope == unix.RT_SCOPE_LINK {
					continue
				}
				if addr.IPNet == nil {
					return fmt.Errorf("unsupported address on %s", link.Name)
				}
				ones, _ := addr.Mask.Size()
				link.Addresses = append(link.Addresses, fmt.Sprintf("%s/%d", addr.IP.String(), ones))
			}
			if link.Kind == "wireguard" {
				link.WireGuard, err = a.observeWireGuard(link.Name, hints)
				if err != nil {
					return err
				}
			}
			observed.Interfaces = append(observed.Interfaces, link)
		}
		a.observeDHCPRelay(observed.Interfaces)
		routes, err := ownedRoutes(h)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if r.Dst == nil || byIndex[r.LinkIndex] == "" || r.Src != nil || len(r.MultiPath) != 0 || r.Type != unix.RTN_UNICAST {
				return fmt.Errorf("unsupported externally modified owned route")
			}
			destination := r.Dst.String()
			gateway := ""
			if r.Gw != nil {
				gateway = r.Gw.String()
			}
			observed.Routes = append(observed.Routes, Route{Destination: destination, Gateway: gateway, Interface: byIndex[r.LinkIndex], Table: r.Table, Metric: r.Priority})
		}
		rules, err := ownedRules(h)
		if err != nil {
			return err
		}
		for _, r := range rules {
			if !simpleRule(r) {
				return fmt.Errorf("unsupported externally modified owned policy rule")
			}
			observed.Rules = append(observed.Rules, Rule{Source: ruleSource(r), Table: r.Table, Priority: r.Priority})
		}
		observed.Firewall, err = observeFirewall()
		if err == nil {
			observed.Softflowd = a.observeServices(ctx, hints.Softflowd)
			err = ctx.Err()
		}
		return err
	})
	if err == nil {
		observed.Kernel, err = a.ReadKernel(ctx, hints.Kernel)
	}
	observed.Normalize()
	return observed, err
}

func (a *linuxAdapter) observeWireGuard(name string, hints Config) (*WireGuard, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	d, err := client.Device(name)
	if err != nil {
		return nil, err
	}
	w := &WireGuard{ListenPort: d.ListenPort}
	for _, hint := range hints.Interfaces {
		if hint.Name == name && hint.WireGuard != nil {
			key, err := a.privateKey(hint.WireGuard.KeyRef)
			if err != nil {
				return nil, err
			}
			if key.PublicKey() == d.PublicKey {
				w.KeyRef = hint.WireGuard.KeyRef
			}
		}
	}
	for _, peer := range d.Peers {
		p := Peer{PublicKey: peer.PublicKey.String(), Keepalive: int(peer.PersistentKeepaliveInterval / time.Second)}
		if peer.Endpoint != nil {
			p.Endpoint = peer.Endpoint.String()
		}
		for _, prefix := range peer.AllowedIPs {
			p.AllowedIPs = append(p.AllowedIPs, prefix.String())
		}
		w.Peers = append(w.Peers, p)
	}
	return w, nil
}

func ownedRoutes(h *netlink.Handle) ([]netlink.Route, error) {
	routes, err := h.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Protocol: ownedProtocol, Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	var owned []netlink.Route
	for _, r := range routes {
		if r.Table >= 10000 && r.Table <= 19999 {
			owned = append(owned, r)
		}
	}
	return owned, nil
}

func ruleSource(r netlink.Rule) string {
	if r.Src != nil {
		return r.Src.String()
	}
	if r.Family == netlink.FAMILY_V4 {
		return "0.0.0.0/0"
	}
	return "::/0"
}

func simpleRule(r netlink.Rule) bool {
	return r.Dst == nil && r.Mark == 0 && r.Mask == nil && r.IifName == "" && r.OifName == "" &&
		!r.Invert && r.Goto < 0 && r.Flow < 0 && r.SuppressIfgroup < 0 && r.SuppressPrefixlen < 0 &&
		r.Dport == nil && r.Sport == nil && r.UIDRange == nil && r.IPProto == 0 &&
		r.Tos == 0 && r.TunID == 0 && r.Type == unix.RTN_UNICAST
}

func ownedRules(_ *netlink.Handle) ([]netlink.Rule, error) {
	conn, err := rtnetlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var result []netlink.Rule
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		data := make([]byte, 12)
		data[0] = byte(family)
		messages, err := conn.Execute(rtnetlink.Message{Header: rtnetlink.Header{Type: unix.RTM_GETRULE, Flags: rtnetlink.Request | rtnetlink.Dump}, Data: data})
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			r, owned, err := decodeOwnedRule(message.Data)
			if err != nil {
				return nil, err
			}
			if owned {
				result = append(result, r)
			}
		}
	}
	return result, nil
}

// netlink v1.3.1's RuleList drops the rule action/type. Decode owned rules
// directly so a blackhole or unreachable rule cannot look like a table lookup.
func decodeOwnedRule(data []byte) (netlink.Rule, bool, error) {
	if len(data) < 12 {
		return netlink.Rule{}, false, fmt.Errorf("short policy-rule message")
	}
	msg := nl.DeserializeRtMsg(data)
	attrs, err := nl.ParseRouteAttr(data[12:])
	if err != nil {
		return netlink.Rule{}, false, err
	}
	r := netlink.NewRule()
	r.Priority = 0
	for _, attr := range attrs {
		if attr.Attr.Type == nl.FRA_PRIORITY {
			if len(attr.Value) != 4 {
				return *r, false, fmt.Errorf("invalid policy-rule priority")
			}
			r.Priority = int(nl.NativeEndian().Uint32(attr.Value))
		}
	}
	if r.Priority < 10000 || r.Priority > 19999 {
		return *r, false, nil
	}
	r.Family, r.Type, r.Table, r.Tos = int(msg.Family), msg.Type, int(msg.Table), uint(msg.Tos)
	if msg.Flags != 0 {
		return *r, true, fmt.Errorf("unsupported owned policy-rule flags")
	}
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.FRA_PRIORITY:
		case unix.RTA_TABLE:
			if len(attr.Value) != 4 {
				return *r, true, fmt.Errorf("invalid policy-rule table")
			}
			r.Table = int(nl.NativeEndian().Uint32(attr.Value))
		case nl.FRA_SRC:
			bits := 128
			if r.Family == netlink.FAMILY_V4 {
				bits = 32
			}
			if len(attr.Value) != bits/8 || int(msg.Src_len) > bits {
				return *r, true, fmt.Errorf("invalid policy-rule source")
			}
			r.Src = &net.IPNet{IP: append(net.IP(nil), attr.Value...), Mask: net.CIDRMask(int(msg.Src_len), bits)}
		case nl.FRA_PROTOCOL:
			if len(attr.Value) != 1 {
				return *r, true, fmt.Errorf("invalid policy-rule protocol")
			}
			r.Protocol = attr.Value[0]
		case nl.FRA_SUPPRESS_PREFIXLEN, nl.FRA_SUPPRESS_IFGROUP:
			if len(attr.Value) != 4 || nl.NativeEndian().Uint32(attr.Value) != ^uint32(0) {
				return *r, true, fmt.Errorf("unsupported owned policy-rule suppression")
			}
		default:
			return *r, true, fmt.Errorf("unsupported owned policy-rule attribute %d", attr.Attr.Type)
		}
	}
	return *r, true, nil
}

func (a *linuxAdapter) Reconcile(ctx context.Context, target Config) error {
	if err := a.WriteKernel(ctx, target.Kernel); err != nil {
		return err
	}
	return a.inNamespace(ctx, func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		if err := a.preflightLinks(h, target); err != nil {
			return err
		}
		if err := a.preflightDHCPRelay(ctx, target.Interfaces); err != nil {
			return err
		}
		if a.relay != nil {
			if err := a.relay.StopChanged(ctx, target.Interfaces); err != nil {
				return err
			}
		}
		if a.flows != nil {
			if err := a.flows.StopChanged(ctx, target.Softflowd); err != nil {
				return err
			}
		}
		links, err := h.LinkList()
		if err != nil {
			return err
		}
		existing := map[string]netlink.Link{}
		for _, link := range links {
			existing[link.Attrs().Name] = link
		}
		wanted := map[string]bool{"lo": true}
		for name := range a.parents {
			wanted[name] = true
		}
		ordered, err := orderedInterfaces(target.Interfaces)
		if err != nil {
			return err
		}
		for _, link := range ordered {
			if err := ctx.Err(); err != nil {
				return err
			}
			wanted[link.Name] = true
			l, found := existing[link.Name]
			if found && l.Type() != link.Kind {
				return fmt.Errorf("%s has conflicting interface kind", link.Name)
			}
			if found && link.VLAN != nil {
				vlan, ok := l.(*netlink.Vlan)
				parent, parentErr := h.LinkByName(link.VLAN.Parent)
				if parentErr != nil {
					return parentErr
				}
				if !ok || vlan.VlanId != link.VLAN.ID || vlan.ParentIndex != parent.Attrs().Index || vlan.VlanProtocol != netlink.VLAN_PROTOCOL_8021Q {
					return fmt.Errorf("existing VLAN %s has conflicting identity", link.Name)
				}
			}
			if !found {
				attrs := netlink.NewLinkAttrs()
				attrs.Name = link.Name
				switch link.Kind {
				case "dummy":
					l = &netlink.Dummy{LinkAttrs: attrs}
				case "wireguard":
					l = &netlink.GenericLink{LinkAttrs: attrs, LinkType: "wireguard"}
				case "vlan":
					parent, err := h.LinkByName(link.VLAN.Parent)
					if err != nil {
						return err
					}
					attrs.ParentIndex = parent.Attrs().Index
					l = &netlink.Vlan{LinkAttrs: attrs, VlanId: link.VLAN.ID, VlanProtocol: netlink.VLAN_PROTOCOL_8021Q}
				default:
					return fmt.Errorf("unsupported link kind %s", link.Kind)
				}
				if err := h.LinkAdd(l); err != nil {
					return fmt.Errorf("create %s: %w", link.Name, err)
				}
				l, err = h.LinkByName(link.Name)
				if err != nil {
					return err
				}
			}
			if err := h.LinkSetMTU(l, link.MTU); err != nil {
				return err
			}
			if err := reconcileAddresses(h, l, link.Addresses); err != nil {
				return err
			}
			if link.WireGuard != nil {
				current, err := a.observeWireGuard(link.Name, target)
				if err != nil {
					return err
				}
				before, after := EmptyConfig(), EmptyConfig()
				before.Interfaces = []Interface{{WireGuard: current}}
				after.Interfaces = []Interface{{WireGuard: link.WireGuard}}
				if !Equal(before, after) {
					if err := a.configureWireGuard(link.Name, *link.WireGuard); err != nil {
						return err
					}
				}
			}
			if link.Up {
				err = h.LinkSetUp(l)
			} else {
				err = h.LinkSetDown(l)
			}
			if err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := reconcileRoutes(h, target.Routes); err != nil {
			return err
		}
		if err := reconcileRules(h, target.Rules); err != nil {
			return err
		}
		if err := reconcileFirewall(target.Firewall); err != nil {
			return err
		}
		for _, link := range deletionOrder(links) {
			if !wanted[link.Attrs().Name] {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := h.LinkDel(link); err != nil {
					return fmt.Errorf("delete %s: %w", link.Attrs().Name, err)
				}
			}
		}
		if a.flows != nil {
			if err := a.flows.Reconcile(ctx, target.Softflowd); err != nil {
				return err
			}
		}
		for _, service := range target.Softflowd {
			if service.Enabled && a.flows == nil {
				return fmt.Errorf("softflowd integration is unavailable")
			}
			if a.relay != nil {
				return a.relay.Reconcile(ctx, target.Interfaces)
			}
		}
		return ctx.Err()
	})
}

func reconcileAddresses(h *netlink.Handle, link netlink.Link, target []string) error {
	existing, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, prefix := range target {
		wanted[prefix] = true
		addr, err := netlink.ParseAddr(prefix)
		if err != nil {
			return err
		}
		// Disable DAD in this isolated control-plane scope so verification is
		// synchronous. Production physical-interface support needs DAD handling.
		addr.Flags = unix.IFA_F_NODAD
		if err := h.AddrReplace(link, addr); err != nil {
			return err
		}
	}
	for _, addr := range existing {
		if addr.Scope == unix.RT_SCOPE_LINK {
			continue
		}
		ones, _ := addr.Mask.Size()
		if !wanted[fmt.Sprintf("%s/%d", addr.IP.String(), ones)] {
			if err := h.AddrDel(link, &addr); err != nil {
				return err
			}
		}
	}
	return nil
}

func reconcileRoutes(h *netlink.Handle, target []Route) error {
	existing, err := ownedRoutes(h)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, r := range target {
		link, err := h.LinkByName(r.Interface)
		if err != nil {
			return err
		}
		_, dst, err := net.ParseCIDR(r.Destination)
		if err != nil {
			return err
		}
		native := netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Table: r.Table, Priority: r.Metric, Protocol: ownedProtocol, Type: unix.RTN_UNICAST}
		if r.Gateway != "" {
			native.Gw = net.ParseIP(r.Gateway)
		} else {
			native.Scope = netlink.SCOPE_LINK
		}
		if err := h.RouteReplace(&native); err != nil {
			return fmt.Errorf("replace route %s: %w", r.Destination, err)
		}
		wanted[routeKey(r)] = true
	}
	for _, r := range existing {
		if r.Dst == nil {
			return fmt.Errorf("unsupported owned route without destination")
		}
		key := routeKey(Route{Destination: r.Dst.String(), Table: r.Table, Metric: r.Priority})
		if !wanted[key] {
			if err := h.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	return nil
}

func reconcileRules(h *netlink.Handle, target []Rule) error {
	existing, err := ownedRules(h)
	if err != nil {
		return err
	}
	present := map[Rule]bool{}
	for _, r := range existing {
		match := false
		if simpleRule(r) {
			for _, desired := range target {
				if r.Priority == desired.Priority && r.Table == desired.Table && ruleSource(r) == desired.Source {
					match, present[desired] = true, true
					break
				}
			}
		}
		if !match {
			if err := h.RuleDel(&r); err != nil {
				return err
			}
		}
	}
	for _, r := range target {
		if present[r] {
			continue
		}
		rule := netlink.NewRule()
		_, rule.Src, err = net.ParseCIDR(r.Source)
		if err != nil {
			return err
		}
		rule.Family = netlink.FAMILY_V6
		if p, _ := netip.ParsePrefix(r.Source); p.Addr().Is4() {
			rule.Family = netlink.FAMILY_V4
		}
		rule.Priority, rule.Table = r.Priority, r.Table
		if err := h.RuleAdd(rule); err != nil {
			return err
		}
	}
	return nil
}

func (a *linuxAdapter) configureWireGuard(name string, w WireGuard) error {
	key, err := a.privateKey(w.KeyRef)
	if err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	config := wgtypes.Config{PrivateKey: &key, ListenPort: &w.ListenPort, ReplacePeers: true}
	for _, peer := range w.Peers {
		public, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return err
		}
		duration := time.Duration(peer.Keepalive) * time.Second
		p := wgtypes.PeerConfig{PublicKey: public, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &duration}
		if peer.Endpoint != "" {
			endpoint, err := netip.ParseAddrPort(peer.Endpoint)
			if err != nil {
				return err
			}
			p.Endpoint = net.UDPAddrFromAddrPort(endpoint)
		}
		for _, prefix := range peer.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(prefix)
			if err != nil {
				return err
			}
			p.AllowedIPs = append(p.AllowedIPs, *ipnet)
		}
		config.Peers = append(config.Peers, p)
	}
	if err := client.ConfigureDevice(name, config); err != nil {
		return fmt.Errorf("configure WireGuard %s: %w", name, err)
	}
	return nil
}
