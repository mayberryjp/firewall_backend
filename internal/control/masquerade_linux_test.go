package control

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestMasqueradeExpressionsConstrainFamilyAndEgress(t *testing.T) {
	for _, rule := range []MasqueradeRule{
		{Family: "ipv4", OutInterface: "wan"},
		{Family: "ipv4", Source: "10.8.0.0/24", OutInterface: "wan"},
		{Family: "ipv6", Source: "2001:db8::/32", OutInterface: "wan"},
	} {
		expressions := masqueradeExpressions(rule)
		meta, ok := expressions[0].(*expr.Meta)
		if !ok || meta.Key != expr.MetaKeyNFPROTO {
			t.Fatal("missing family guard")
		}
		family, ok := expressions[1].(*expr.Cmp)
		expected := byte(unix.NFPROTO_IPV4)
		if rule.Family == "ipv6" {
			expected = unix.NFPROTO_IPV6
		}
		if !ok || !bytes.Equal(family.Data, []byte{expected}) {
			t.Fatal("wrong family comparison")
		}
		egress, ok := expressions[len(expressions)-3].(*expr.Meta)
		if !ok || egress.Key != expr.MetaKeyOIFNAME {
			t.Fatal("missing egress guard")
		}
		name, ok := expressions[len(expressions)-2].(*expr.Cmp)
		padded := make([]byte, unix.IFNAMSIZ)
		copy(padded, rule.OutInterface)
		if !ok || !bytes.Equal(name.Data, padded) {
			t.Fatal("egress comparison must include exact padded interface name")
		}
		if _, ok := expressions[len(expressions)-1].(*expr.Masq); !ok {
			t.Fatal("missing masquerade action")
		}
	}
	if len(firewallExpressions(FirewallRule{Action: "accept"})) != 1 {
		t.Fatal("unconditional filtering behavior changed")
	}
}

func probeMasqueradePacket(t *testing.T, adapter Adapter, localPort, destinationPort int, translated bool) int {
	t.Helper()
	native, ok := adapter.(*linuxAdapter)
	if !ok {
		t.Fatal("native adapter required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sourcePort := 0
	err := native.inNamespace(ctx, func() error {
		socket, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: localPort},
			&net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: destinationPort})
		if err != nil {
			return err
		}
		defer socket.Close()
		if err := socket.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		if _, err := socket.Write([]byte("netcontrol-masquerade-probe")); err != nil {
			return err
		}
		local, ok := socket.LocalAddr().(*net.UDPAddr)
		if !ok {
			return fmt.Errorf("unexpected UDP local address type")
		}
		sourcePort = local.Port
		handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
		if err != nil {
			return err
		}
		defer handle.Close()
		flows, err := handle.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		want := "192.0.2.11"
		if translated {
			want = "192.0.2.10"
		}
		for _, flow := range flows {
			if flow.Forward.Protocol == unix.IPPROTO_UDP && flow.Forward.SrcIP.String() == "192.0.2.11" &&
				flow.Forward.DstIP.String() == "192.0.2.20" && int(flow.Forward.SrcPort) == sourcePort &&
				int(flow.Forward.DstPort) == destinationPort {
				if flow.Reverse.DstIP.String() != want {
					return fmt.Errorf("conntrack reply destination %s, want %s", flow.Reverse.DstIP, want)
				}
				return nil
			}
		}
		return fmt.Errorf("probe flow missing from conntrack table")
	})
	if err != nil {
		t.Fatal(err)
	}
	return sourcePort
}
