package control

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type nativeGatewaySession struct {
	config    GatewayMonitor
	conn      net.PacketConn
	routes    *netlink.Handle
	linkIndex int
	protocol  int
	id        int
	nonce     [16]byte
	target    *net.IPAddr
	replies   chan gatewayReply
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
	closeErr  error
}

func (a *linuxAdapter) preflightGateways(c Config) error {
	families := map[int]bool{}
	for _, m := range c.GatewayMonitors {
		if !m.Enabled {
			continue
		}
		if !a.allowGatewayMonitoring {
			return fmt.Errorf("%w: native gateway monitoring requires the operator -gateway-monitoring flag", ErrValidation)
		}
		family, protocol := unix.AF_INET6, unix.IPPROTO_ICMPV6
		if netip.MustParseAddr(m.SourceAddress).Is4() {
			family, protocol = unix.AF_INET, unix.IPPROTO_ICMP
		}
		if families[family] {
			continue
		}
		fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
		if err != nil {
			return fmt.Errorf("gateway monitor raw socket privilege: %w", err)
		}
		if err := unix.Close(fd); err != nil {
			return err
		}
		families[family] = true
	}
	return nil
}

// Called on the adapter's pinned namespace thread; sockets retain that scope.
func openNativeGatewaySession(ctx context.Context, config GatewayMonitor) (gatewaySession, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (gatewaySession, error) { h.Close(); return nil, err }
	if err := h.SetSocketTimeout(250 * time.Millisecond); err != nil {
		return fail(err)
	}
	link, err := h.LinkByName(config.Interface)
	if err != nil {
		return fail(err)
	}
	target := netip.MustParseAddr(config.Target)
	s := &nativeGatewaySession{config: config, routes: h, linkIndex: link.Attrs().Index,
		target: &net.IPAddr{IP: net.ParseIP(config.Target)}, protocol: 58,
		replies: make(chan gatewayReply, 32), stop: make(chan struct{}), done: make(chan struct{})}
	if target.Is6() && target.IsLinkLocalUnicast() {
		s.target.Zone = config.Interface
	}
	if err := s.checkPath(); err != nil {
		return fail(err)
	}
	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fail(err)
	}
	copy(s.nonce[:], random[:16])
	s.id = int(binary.BigEndian.Uint16(random[16:]))
	network := "ip6:ipv6-icmp"
	if target.Is4() {
		network, s.protocol = "ip4:icmp", 1
	}
	listen := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, config.Interface)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	s.conn, err = listen.ListenPacket(ctx, network, config.SourceAddress)
	if err != nil {
		return fail(err)
	}
	go s.read()
	return s, nil
}

func (s *nativeGatewaySession) checkPath() error {
	link, err := s.routes.LinkByName(s.config.Interface)
	if err != nil {
		return err
	}
	if link.Attrs().Index != s.linkIndex || link.Attrs().Flags&net.FlagUp == 0 {
		return fmt.Errorf("monitor interface identity/up state changed")
	}
	addresses, err := s.routes.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	source := net.ParseIP(s.config.SourceAddress)
	found := false
	for _, address := range addresses {
		if address.IP.Equal(source) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("monitor source address is no longer configured")
	}
	options := &netlink.RouteGetOptions{SrcAddr: source, FIBMatch: true}
	if s.target.Zone != "" {
		options.Oif = s.config.Interface
	}
	routes, err := s.routes.RouteGetWithOptions(s.target.IP, options)
	if err != nil {
		return err
	}
	if len(routes) != 1 {
		return fmt.Errorf("ambiguous monitor route")
	}
	r := routes[0]
	gatewayOK := r.Gw.Equal(net.ParseIP(s.config.Gateway)) ||
		(s.config.Target == s.config.Gateway && len(r.Gw) == 0)
	if r.LinkIndex != s.linkIndex || r.Table != s.config.RoutingTable || r.Type != unix.RTN_UNICAST ||
		len(r.MultiPath) != 0 || !gatewayOK {
		return fmt.Errorf("effective monitor route does not match configured interface, gateway and table")
	}
	return nil
}

func (s *nativeGatewaySession) Send(ctx context.Context, sequence uint64) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if err := s.checkPath(); err != nil {
		return time.Time{}, err
	}
	payload := make([]byte, 24)
	copy(payload, s.nonce[:])
	binary.BigEndian.PutUint64(payload[16:], sequence)
	var kind icmp.Type = ipv6.ICMPTypeEchoRequest
	if s.protocol == 1 {
		kind = ipv4.ICMPTypeEcho
	}
	message := icmp.Message{Type: kind, Body: &icmp.Echo{ID: s.id, Seq: int(sequence & 0xffff), Data: payload}}
	wire, err := message.Marshal(nil)
	if err != nil {
		return time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		return time.Time{}, err
	}
	sent := time.Now()
	n, err := s.conn.WriteTo(wire, s.target)
	if err != nil {
		return time.Time{}, err
	}
	if n != len(wire) {
		return time.Time{}, fmt.Errorf("short ICMP probe write")
	}
	return sent, nil
}

func (s *nativeGatewaySession) read() {
	defer close(s.done)
	buffer := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFrom(buffer)
		now := time.Now()
		if err != nil {
			select {
			case <-s.stop:
			case s.replies <- gatewayReply{err: err}:
			}
			return
		}
		address, ok := from.(*net.IPAddr)
		if !ok || !address.IP.Equal(s.target.IP) {
			continue
		}
		sequence, valid := gatewayEchoSequence(s.protocol, s.id, s.nonce[:], buffer[:n])
		if !valid {
			continue
		}
		select {
		case s.replies <- gatewayReply{sequence: sequence, received: now}:
		case <-s.stop:
			return
		}
	}
}

func (s *nativeGatewaySession) Replies() <-chan gatewayReply { return s.replies }

func (s *nativeGatewaySession) Close() error {
	s.once.Do(func() {
		close(s.stop)
		s.closeErr = s.conn.Close()
		<-s.done
		s.routes.Close()
	})
	return s.closeErr
}

func (a *linuxAdapter) GatewayStatistics(ctx context.Context, hints Config) ([]GatewayMonitorStatistics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.gateways.Statistics(hints.GatewayMonitors), nil
}
