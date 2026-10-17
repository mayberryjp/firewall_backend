package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func (a *linuxAdapter) Statistics(ctx context.Context, query StatisticsQuery, hints Config) (NetworkStatistics, error) {
	if err := query.Validate(); err != nil {
		return NetworkStatistics{}, err
	}
	result := newNetworkStatistics(a.Scope())
	err := a.inNamespace(ctx, func() error {
		if query.Section != StatisticsProtocols {
			links, err := readInterfaceStatistics(ctx, query.Interface)
			if err != nil {
				return err
			}
			for _, link := range links {
				if query.Interface != "" && link.Name != query.Interface {
					continue
				}
				link.Ownership = "unmanaged"
				if link.Kind == "loopback" {
					link.Ownership = "loopback"
				}
				for _, managed := range hints.Interfaces {
					if managed.Name == link.Name {
						link.Ownership = "managed"
						break
					}
				}
				if parent, ok := a.parents[link.Name]; ok {
					link.Ownership = "adopted_parent"
					if parent.Index != link.Index || parent.MAC != link.MAC || parent.Kind != link.Kind {
						link.Ownership = "adopted_parent_identity_changed"
					}
				}
				if link.Status != "available" {
					result.Sample.Status = "partial"
				}
				result.Interfaces = append(result.Interfaces, link)
			}
			if query.Interface != "" && len(result.Interfaces) == 0 {
				return fmt.Errorf("%w: %s", ErrStatisticsInterfaceNotFound, query.Interface)
			}
		}
		if query.Section != StatisticsInterfaces {
			available := 0
			for _, name := range []string{"snmp", "netstat", "snmp6"} {
				if err := ctx.Err(); err != nil {
					return err
				}
				source, err := readProtocolStatistics(name)
				if err != nil {
					return err
				}
				if source.Status == "available" {
					available++
				} else {
					result.Sample.Status = "partial"
				}
				result.Protocols = append(result.Protocols, source)
			}
			if available == 0 && query.Section == StatisticsProtocols {
				return fmt.Errorf("no protocol statistics sources are available in the managed namespace")
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return NetworkStatistics{}, err
	}
	slices.SortFunc(result.Interfaces, func(a, b InterfaceStatistics) int { return strings.Compare(a.Name, b.Name) })
	result.Sample.CollectedAt = time.Now().UTC()
	return result, nil
}

func readInterfaceStatistics(ctx context.Context, name string) ([]InterfaceStatistics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	socket, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer socket.Close()
	timeout := 5 * time.Second
	if limit, ok := ctx.Deadline(); ok && time.Until(limit) < timeout {
		timeout = max(time.Until(limit), time.Microsecond)
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := socket.SetSendTimeout(&tv); err != nil {
		return nil, err
	}
	if err := socket.SetReceiveTimeout(&tv); err != nil {
		return nil, err
	}
	flags := unix.NLM_F_DUMP
	if name != "" {
		flags = 0
	}
	request := nl.NewNetlinkRequest(unix.RTM_GETLINK, flags)
	request.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: socket}}
	request.AddData(nl.NewIfInfomsg(unix.AF_UNSPEC))
	if name != "" {
		request.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, []byte(name+"\x00")))
	}
	messages, err := request.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWLINK)
	if err != nil {
		if name != "" && (errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO)) {
			return nil, fmt.Errorf("%w: %s", ErrStatisticsInterfaceNotFound, name)
		}
		return nil, errors.Join(fmt.Errorf("read interface statistics: %w", err), ctx.Err())
	}
	result := make([]InterfaceStatistics, 0, len(messages))
	names := map[string]bool{}
	indices := map[int]bool{}
	for _, message := range messages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		link, err := decodeInterfaceStatistics(message)
		if err != nil {
			return nil, err
		}
		if names[link.Name] || indices[link.Index] {
			return nil, fmt.Errorf("inconsistent interface statistics dump")
		}
		names[link.Name], indices[link.Index] = true, true
		result = append(result, link)
	}
	return result, ctx.Err()
}

func decodeInterfaceStatistics(data []byte) (InterfaceStatistics, error) {
	if len(data) < unix.SizeofIfInfomsg {
		return InterfaceStatistics{}, fmt.Errorf("short interface statistics message")
	}
	order := nl.NativeEndian()
	link := InterfaceStatistics{Index: int(int32(order.Uint32(data[4:8]))), Kind: "device", OperState: "unknown", Status: "available"}
	flags := order.Uint32(data[8:12])
	link.AdminUp = flags&unix.IFF_UP != 0
	if flags&unix.IFF_LOOPBACK != 0 {
		link.Kind = "loopback"
	}
	attrs, err := nl.ParseRouteAttr(data[unix.SizeofIfInfomsg:])
	if err != nil {
		return InterfaceStatistics{}, err
	}
	values := map[uint16][]byte{}
	for _, attr := range attrs {
		kind := attr.Attr.Type &^ uint16(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER)
		switch kind {
		case unix.IFLA_IFNAME, unix.IFLA_MTU, unix.IFLA_ADDRESS, unix.IFLA_OPERSTATE, unix.IFLA_LINKINFO, unix.IFLA_STATS, unix.IFLA_STATS64:
		default:
			continue
		}
		if _, duplicate := values[kind]; duplicate {
			return InterfaceStatistics{}, fmt.Errorf("duplicate interface attribute %d", kind)
		}
		values[kind] = attr.Value
	}
	name := values[unix.IFLA_IFNAME]
	if len(name) < 2 || name[len(name)-1] != 0 {
		return InterfaceStatistics{}, fmt.Errorf("missing interface name")
	}
	link.Name = string(name[:len(name)-1])
	if !validStatisticsName(link.Name) || link.Index <= 0 {
		return InterfaceStatistics{}, fmt.Errorf("invalid interface identity in statistics")
	}
	mtu := values[unix.IFLA_MTU]
	if len(mtu) != 4 {
		return InterfaceStatistics{}, fmt.Errorf("missing or invalid interface MTU")
	}
	link.MTU = int(order.Uint32(mtu))
	if address, ok := values[unix.IFLA_ADDRESS]; ok {
		link.MAC = net.HardwareAddr(address).String()
	}
	if state, ok := values[unix.IFLA_OPERSTATE]; ok {
		states := []string{"unknown", "not_present", "down", "lower_layer_down", "testing", "dormant", "up"}
		if len(state) != 1 || int(state[0]) >= len(states) {
			return InterfaceStatistics{}, fmt.Errorf("invalid operational state for %s", link.Name)
		}
		link.OperState = states[state[0]]
	}
	if info, ok := values[unix.IFLA_LINKINFO]; ok {
		nested, err := nl.ParseRouteAttr(info)
		if err != nil {
			return InterfaceStatistics{}, err
		}
		kindSeen := false
		for _, attr := range nested {
			if attr.Attr.Type&^uint16(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER) == unix.IFLA_INFO_KIND {
				if kindSeen {
					return InterfaceStatistics{}, fmt.Errorf("duplicate interface kind")
				}
				kindSeen = true
				if len(attr.Value) < 2 || attr.Value[len(attr.Value)-1] != 0 {
					return InterfaceStatistics{}, fmt.Errorf("invalid interface kind")
				}
				link.Kind = string(attr.Value[:len(attr.Value)-1])
			}
		}
	}
	switch {
	case values[unix.IFLA_STATS64] != nil:
		link.CounterBits = 64
		link.Counters, err = decodeInterfaceCounters(values[unix.IFLA_STATS64], 64, order)
	case values[unix.IFLA_STATS] != nil:
		link.CounterBits = 32
		link.Counters, err = decodeInterfaceCounters(values[unix.IFLA_STATS], 32, order)
	default:
		link.Status, link.Error = "unavailable", "kernel supplied no interface counters"
	}
	if err != nil {
		return InterfaceStatistics{}, fmt.Errorf("%s: %w", link.Name, err)
	}
	return link, nil
}

func readProtocolStatistics(name string) (ProtocolStatistics, error) {
	if name != "snmp" && name != "netstat" && name != "snmp6" {
		return ProtocolStatistics{}, fmt.Errorf("unsupported protocol statistics source")
	}
	result := ProtocolStatistics{Name: name, Status: "available"}
	// /proc/net follows the process leader, not this namespace-pinned thread.
	path := "/proc/thread-self/net/" + name
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		result.Status, result.Error = "unavailable", "kernel source is not exposed in this namespace"
		return result, nil
	}
	if err != nil {
		return ProtocolStatistics{}, fmt.Errorf("open protocol statistics %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), path)
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return ProtocolStatistics{}, errors.Join(err, f.Close())
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return ProtocolStatistics{}, errors.Join(fmt.Errorf("protocol statistics source is not procfs"), f.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxProtocolStatisticsBytes+1))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return ProtocolStatistics{}, fmt.Errorf("read protocol statistics %s: %w", name, err)
	}
	groups, err := parseProtocolStatistics(string(data), name == "snmp6")
	if err != nil {
		return ProtocolStatistics{}, fmt.Errorf("parse protocol statistics %s: %w", name, err)
	}
	result.Groups = groups
	return result, nil
}
