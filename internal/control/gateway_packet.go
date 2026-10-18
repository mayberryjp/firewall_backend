package control

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func gatewayEchoSequence(protocol, id int, nonce []byte, wire []byte) (uint64, bool) {
	if protocol != 1 && protocol != 58 {
		return 0, false
	}
	if protocol == 1 {
		var sum uint32
		for i := 0; i < len(wire); i += 2 {
			sum += uint32(wire[i]) << 8
			if i+1 < len(wire) {
				sum += uint32(wire[i+1])
			}
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		if sum != 0xffff {
			return 0, false
		}
	}
	m, err := icmp.ParseMessage(protocol, wire)
	if err != nil || m.Code != 0 {
		return 0, false
	}
	if (protocol == 1 && m.Type != ipv4.ICMPTypeEchoReply) ||
		(protocol == 58 && m.Type != ipv6.ICMPTypeEchoReply) {
		return 0, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || echo.ID != id || len(echo.Data) != 24 || !bytes.Equal(echo.Data[:16], nonce) {
		return 0, false
	}
	sequence := binary.BigEndian.Uint64(echo.Data[16:])
	return sequence, echo.Seq == int(sequence&0xffff)
}
