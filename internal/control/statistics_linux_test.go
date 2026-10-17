package control

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func statisticsLinkMessage(extra ...[]byte) []byte {
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = 7
	msg.Flags = unix.IFF_UP | unix.IFF_LOOPBACK
	data := append([]byte(nil), msg.Serialize()...)
	for _, attr := range [][]byte{
		nl.NewRtAttr(unix.IFLA_IFNAME, []byte("lo\x00")).Serialize(),
		nl.NewRtAttr(unix.IFLA_MTU, nl.Uint32Attr(65536)).Serialize(),
		nl.NewRtAttr(unix.IFLA_OPERSTATE, []byte{0}).Serialize(),
	} {
		data = append(data, attr...)
	}
	for _, attr := range extra {
		data = append(data, attr...)
	}
	return data
}

func TestLinuxInterfaceStatisticsMessageDecoding(t *testing.T) {
	order := nl.NativeEndian()
	wide := nl.NewRtAttr(unix.IFLA_STATS64, counterFixture(64, 25, order)).Serialize()
	narrow := nl.NewRtAttr(unix.IFLA_STATS, counterFixture(32, 23, order)).Serialize()
	link, err := decodeInterfaceStatistics(statisticsLinkMessage(narrow, wide))
	if err != nil || link.Name != "lo" || link.Index != 7 || link.Kind != "loopback" || !link.AdminUp || link.MTU != 65536 ||
		link.CounterBits != 64 || link.Counters == nil || link.Counters.TxBytes != 4 {
		t.Fatalf("%+v %v", link, err)
	}
	link, err = decodeInterfaceStatistics(statisticsLinkMessage(narrow))
	if err != nil || link.CounterBits != 32 || link.Counters.RxNoHandler != nil {
		t.Fatalf("%+v %v", link, err)
	}
	link, err = decodeInterfaceStatistics(statisticsLinkMessage())
	if err != nil || link.Status != "unavailable" || link.Counters != nil || link.Error == "" {
		t.Fatalf("missing statistics fabricated: %+v %v", link, err)
	}
	kind := nl.NewRtAttr(unix.IFLA_INFO_KIND, []byte("dummy\x00")).Serialize()
	link, err = decodeInterfaceStatistics(statisticsLinkMessage(wide, nl.NewRtAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, kind).Serialize()))
	if err != nil || link.Kind != "dummy" {
		t.Fatalf("%+v %v", link, err)
	}
	unknown := nl.NewRtAttr(0x3fff, []byte{1}).Serialize()
	if _, err := decodeInterfaceStatistics(statisticsLinkMessage(wide, unknown, unknown)); err != nil {
		t.Fatal("unknown repeatable attributes should not prevent diagnostics", err)
	}
	for _, data := range [][]byte{
		{}, make([]byte, unix.SizeofIfInfomsg), statisticsLinkMessage(wide, wide),
		statisticsLinkMessage(nl.NewRtAttr(unix.IFLA_STATS64, []byte{1, 2, 3}).Serialize()),
		statisticsLinkMessage(nl.NewRtAttr(unix.IFLA_IFNAME, []byte("bad\x00")).Serialize()),
		statisticsLinkMessage(nl.NewRtAttr(unix.IFLA_OPERSTATE, []byte{1, 2}).Serialize()),
	} {
		if _, err := decodeInterfaceStatistics(data); err == nil {
			t.Fatal("malformed netlink statistics accepted")
		}
	}
	if _, err := readProtocolStatistics("../sys/kernel/random/boot_id"); err == nil {
		t.Fatal("unallowlisted proc source accepted")
	}
}

func loopbackStatistics(t *testing.T, snapshot NetworkStatistics) InterfaceStatistics {
	t.Helper()
	for _, link := range snapshot.Interfaces {
		if link.Name == "lo" {
			return link
		}
	}
	t.Fatal("loopback absent from kernel statistics")
	return InterfaceStatistics{}
}

func sendStatisticsPackets(packets, size int) error {
	server, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(server)
	if err := unix.Bind(server, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return err
	}
	address, err := unix.Getsockname(server)
	if err != nil {
		return err
	}
	target, ok := address.(*unix.SockaddrInet4)
	if !ok {
		return fmt.Errorf("unexpected UDP socket address type")
	}
	timeout := unix.NsecToTimeval((5 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(server, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return err
	}
	client, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(client)
	if err := unix.Connect(client, target); err != nil {
		return err
	}
	payload, buffer := make([]byte, size), make([]byte, size+1)
	for range packets {
		if n, err := unix.Write(client, payload); err != nil {
			return err
		} else if n != len(payload) {
			return fmt.Errorf("short UDP send")
		}
		if n, err := unix.Read(server, buffer); err != nil {
			return err
		} else if n != len(payload) {
			return fmt.Errorf("unexpected UDP packet length")
		}
	}
	return nil
}

func TestLinuxNetworkStatisticsPacketsAndNamespaceIsolation(t *testing.T) {
	namespace := extensionNamespace(t)
	adapter, err := NewLinuxAdapter(namespace, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Error(err)
		}
	})
	native := adapter.(*linuxAdapter)
	ctx := context.Background()
	err = native.inNamespace(ctx, func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		lo, err := h.LinkByName("lo")
		if err != nil {
			return err
		}
		if err := h.LinkSetUp(lo); err != nil {
			return err
		}
		return h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "unmanaged", MTU: 1500}})
	})
	if err != nil {
		t.Fatal(err)
	}
	e := testEngine(t, testStore(t), adapter)
	journal := e.Snapshot()
	before, err := e.Statistics(ctx, StatisticsQuery{Section: StatisticsAll})
	if err != nil {
		t.Fatal(err)
	}
	old := loopbackStatistics(t, before)
	if old.Counters == nil || old.Ownership != "loopback" || old.CounterBits != 64 {
		t.Fatalf("missing native 64-bit counters: %+v", old)
	}
	const packets, size = 16, 256
	if err := native.inNamespace(ctx, func() error { return sendStatisticsPackets(packets, size) }); err != nil {
		t.Fatal(err)
	}
	after, err := e.Statistics(ctx, StatisticsQuery{Section: StatisticsAll})
	if err != nil {
		t.Fatal(err)
	}
	current := loopbackStatistics(t, after)
	if current.Index != old.Index || after.Sample.Scope != native.Scope() {
		t.Fatal("counter identity lost")
	}
	if current.Counters.RxPackets < old.Counters.RxPackets+packets || current.Counters.TxPackets < old.Counters.TxPackets+packets ||
		current.Counters.RxBytes < old.Counters.RxBytes+packets*size || current.Counters.TxBytes < old.Counters.TxBytes+packets*size {
		t.Fatalf("traffic not counted: before %+v after %+v", old.Counters, current.Counters)
	}
	udp := func(s NetworkStatistics, field string) uint64 {
		t.Helper()
		for _, source := range s.Protocols {
			if source.Name == "snmp" && source.Status == "available" {
				n, err := strconv.ParseUint(source.Groups["Udp"][field], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
		}
		t.Fatal("namespace UDP statistics unavailable")
		return 0
	}
	for _, field := range []string{"OutDatagrams", "InDatagrams"} {
		if udp(after, field) != udp(before, field)+packets {
			t.Fatalf("%s did not count exactly the namespace's packets; check thread-self proc collection", field)
		}
	}
	single, err := e.Statistics(ctx, StatisticsQuery{Section: StatisticsInterfaces, Interface: "lo"})
	if err != nil || len(single.Interfaces) != 1 || single.Interfaces[0].Name != "lo" {
		t.Fatalf("%+v %v", single, err)
	}
	if _, err := e.Statistics(ctx, StatisticsQuery{Section: StatisticsInterfaces, Interface: "does-not-exist"}); !errors.Is(err, ErrStatisticsInterfaceNotFound) {
		t.Fatal(err)
	}
	seen := false
	for _, link := range after.Interfaces {
		if link.Name == "unmanaged" {
			seen = true
			if link.Ownership != "unmanaged" {
				t.Fatal(link)
			}
		}
	}
	if !seen {
		t.Fatal("unmanaged link hidden from statistics")
	}
	if !reflect.DeepEqual(journal, e.Snapshot()) {
		t.Fatal("kernel statistics collection changed configuration")
	}
}
