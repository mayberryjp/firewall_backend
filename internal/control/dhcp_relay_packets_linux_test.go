package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func relayTestNamespace(t *testing.T) (*linuxAdapter, string) {
	t.Helper()
	name := extensionNamespace(t)
	adapter, err := NewLinuxAdapter(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Error(err)
		}
	})
	return adapter.(*linuxAdapter), name
}

func relayTestVeth(t *testing.T, router, peer *linuxAdapter, parent, peerName, vlanName string, id int, addresses []string) {
	t.Helper()
	err := router.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		if err := h.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: parent, MTU: 1500}, PeerName: peerName}); err != nil {
			return err
		}
		link, err := h.LinkByName(parent)
		if err != nil {
			return err
		}
		if err := h.LinkSetUp(link); err != nil {
			return err
		}
		other, err := h.LinkByName(peerName)
		if err != nil {
			return err
		}
		return h.LinkSetNsFd(other, int(peer.namespace))
	})
	if err != nil {
		t.Fatal(err)
	}
	err = peer.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		parentLink, err := h.LinkByName(peerName)
		if err != nil {
			return err
		}
		if err := h.LinkSetUp(parentLink); err != nil {
			return err
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name, attrs.ParentIndex = vlanName, parentLink.Attrs().Index
		if err := h.LinkAdd(&netlink.Vlan{LinkAttrs: attrs, VlanId: id, VlanProtocol: netlink.VLAN_PROTOCOL_8021Q}); err != nil {
			return err
		}
		link, err := h.LinkByName(vlanName)
		if err != nil {
			return err
		}
		for _, value := range addresses {
			addr, err := netlink.ParseAddr(value)
			if err != nil {
				return err
			}
			if err := h.AddrAdd(link, addr); err != nil {
				return err
			}
		}
		return h.LinkSetUp(link)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func relayTestSocket(t *testing.T, adapter *linuxAdapter, ip string, port int) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	err := adapter.inNamespace(context.Background(), func() error {
		var err error
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestLinuxDHCPRelayForwardsToEveryServerAndReturnsReply(t *testing.T) {
	options := relayLinuxOptions(t)
	setup, routerName := relayTestNamespace(t)
	clientNS, _ := relayTestNamespace(t)
	serverNS, _ := relayTestNamespace(t)
	relayTestVeth(t, setup, clientNS, "client-parent", "client-peer", "client.100", 100, []string{"192.0.2.100/24"})
	relayTestVeth(t, setup, serverNS, "server-parent", "server-peer", "server.200", 200,
		[]string{"198.51.100.10/24", "198.51.100.20/24"})
	err := serverNS.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		link, err := h.LinkByName("server.200")
		if err != nil {
			return err
		}
		_, destination, err := net.ParseCIDR("192.0.2.0/24")
		if err != nil {
			return err
		}
		return h.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: destination, Gw: net.ParseIP("198.51.100.1")})
	})
	if err != nil {
		t.Fatal(err)
	}
	options.ParentInterfaces = []string{"client-parent", "server-parent"}
	adapter, err := NewLinuxAdapter(routerName, "", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Error(err)
		}
	})
	c := EmptyConfig()
	c.Firewall.Policy = "drop"
	c.Interfaces = []Interface{
		{Name: "lan.100", Kind: "vlan", Role: "lan", MTU: 1500, Up: true, Addresses: []string{"192.0.2.1/24"},
			VLAN:      &VLAN{Parent: "client-parent", ID: 100},
			DHCPRelay: DHCPRelayConfig{Enabled: true, Servers: []string{"198.51.100.10", "198.51.100.20"}}},
		{Name: "wan.200", Kind: "vlan", Role: "wan", MTU: 1500, Up: true, Addresses: []string{"198.51.100.1/24"},
			VLAN: &VLAN{Parent: "server-parent", ID: 200}},
	}
	e := testEngine(t, testStore(t), adapter)
	tx := submit(t, e, 0, c)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	var hardware net.HardwareAddr
	err = clientNS.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		link, err := h.LinkByName("client.100")
		if err != nil {
			return err
		}
		hardware = append(net.HardwareAddr{}, link.Attrs().HardwareAddr...)
		return nil
	})
	if err != nil || len(hardware) != 6 {
		t.Fatalf("client hardware address: %v %v", hardware, err)
	}
	servers := []*net.UDPConn{
		relayTestSocket(t, serverNS, "198.51.100.10", 67),
		relayTestSocket(t, serverNS, "198.51.100.20", 67),
	}
	results := make(chan error, len(servers))
	for _, server := range servers {
		go func(server *net.UDPConn) {
			packet := make([]byte, 1500)
			n, _, err := server.ReadFromUDP(packet)
			if err != nil {
				results <- err
				return
			}
			if n < 244 || packet[0] != 1 || packet[3] != 1 ||
				binary.BigEndian.Uint32(packet[4:8]) != 0x1a2b3c4d ||
				!bytes.Equal(packet[24:28], net.ParseIP("192.0.2.1").To4()) {
				results <- fmt.Errorf("invalid relayed BOOTP request")
				return
			}
			offer := append([]byte{}, packet[:n]...)
			offer[0] = 2
			copy(offer[16:20], net.ParseIP("192.0.2.150").To4())
			address, ok := server.LocalAddr().(*net.UDPAddr)
			if !ok {
				results <- fmt.Errorf("unexpected DHCP server socket address")
				return
			}
			copy(offer[20:24], address.IP.To4())
			copy(offer[240:245], []byte{53, 1, 2, 54, 4})
			copy(offer[245:249], address.IP.To4())
			copy(offer[249:251], []byte{51, 4})
			binary.BigEndian.PutUint32(offer[251:255], 3600)
			offer[255] = 255
			_, err = server.WriteToUDP(offer, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 67})
			results <- err
		}(server)
	}
	client := relayTestSocket(t, clientNS, "0.0.0.0", 68)
	discover := make([]byte, 300)
	discover[0], discover[1], discover[2] = 1, 1, 6
	binary.BigEndian.PutUint32(discover[4:8], 0x1a2b3c4d)
	binary.BigEndian.PutUint16(discover[10:12], 0x8000)
	copy(discover[28:34], hardware)
	copy(discover[236:244], []byte{99, 130, 83, 99, 53, 1, 1, 255})
	if _, err := client.WriteToUDP(discover, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 67}); err != nil {
		t.Fatal(err)
	}
	for range servers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	reply := make([]byte, 1500)
	n, _, err := client.ReadFromUDP(reply)
	if err != nil || n < 244 || reply[0] != 2 || binary.BigEndian.Uint32(reply[4:8]) != 0x1a2b3c4d ||
		!bytes.Equal(reply[16:20], net.ParseIP("192.0.2.150").To4()) {
		t.Fatalf("DHCP offer not returned to the client: %d bytes, %v", n, err)
	}
}
