package control

import (
	"encoding/binary"
	"strconv"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestGatewayEchoMatching(t *testing.T) {
	for _, protocol := range []int{1, 58} {
		t.Run(strconv.Itoa(protocol), func(t *testing.T) {
			nonce := []byte("0123456789abcdef")
			data := append([]byte{}, nonce...)
			data = append(data, make([]byte, 8)...)
			binary.BigEndian.PutUint64(data[16:], 65537)
			var kind icmp.Type = ipv4.ICMPTypeEchoReply
			if protocol == 58 {
				kind = ipv6.ICMPTypeEchoReply
			}
			m := icmp.Message{Type: kind, Body: &icmp.Echo{ID: 42, Seq: 1, Data: data}}
			wire, err := m.Marshal(nil)
			if err != nil {
				t.Fatal(err)
			}
			if seq, valid := gatewayEchoSequence(protocol, 42, nonce, wire); !valid || seq != 65537 {
				t.Fatal("valid reply rejected")
			}
			if _, valid := gatewayEchoSequence(protocol, 43, nonce, wire); valid {
				t.Fatal("foreign identifier accepted")
			}
			if _, valid := gatewayEchoSequence(protocol, 42, []byte("fedcba9876543210"), wire); valid {
				t.Fatal("foreign session accepted")
			}
			echo := m.Body.(*icmp.Echo)
			echo.Seq = 2
			wire, err = m.Marshal(nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, valid := gatewayEchoSequence(protocol, 42, nonce, wire); valid {
				t.Fatal("sequence/payload mismatch accepted")
			}
			if _, valid := gatewayEchoSequence(protocol, 42, nonce, wire[:7]); valid {
				t.Fatal("truncated reply accepted")
			}
			if protocol == 1 {
				wire[3] ^= 1
				if _, valid := gatewayEchoSequence(protocol, 42, nonce, wire); valid {
					t.Fatal("bad checksum accepted")
				}
			}
		})
	}
}

func FuzzGatewayEchoMatching(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, wire []byte) {
		for _, protocol := range []int{1, 58} {
			gatewayEchoSequence(protocol, 42, []byte("0123456789abcdef"), wire)
		}
	})
}
