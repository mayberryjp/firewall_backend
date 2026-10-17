package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func counterFixture(bits, count int, order binary.ByteOrder) []byte {
	data := make([]byte, count*(bits/8))
	for i := 0; i < count; i++ {
		if bits == 64 {
			order.PutUint64(data[i*8:], uint64(i+1))
		} else {
			order.PutUint32(data[i*4:], uint32(i+1))
		}
	}
	return data
}

func TestInterfaceCounterDecodingAndJSONPrecision(t *testing.T) {
	names := []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "multicast", "collisions",
		"rx_length_errors", "rx_over_errors", "rx_crc_errors", "rx_frame_errors", "rx_fifo_errors", "rx_missed_errors",
		"tx_aborted_errors", "tx_carrier_errors", "tx_fifo_errors", "tx_heartbeat_errors", "tx_window_errors", "rx_compressed", "tx_compressed",
		"rx_nohandler", "rx_otherhost_dropped"}
	for _, bits := range []int{32, 64} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			data := counterFixture(bits, 26, order)
			maximum := uint64(^uint32(0))
			if bits == 64 {
				maximum = ^uint64(0)
				order.PutUint64(data[16:], maximum)
			} else {
				order.PutUint32(data[8:], uint32(maximum))
			}
			counters, err := decodeInterfaceCounters(data, bits, order)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(counters)
			if err != nil {
				t.Fatal(err)
			}
			var values map[string]string
			if err := json.Unmarshal(encoded, &values); err != nil {
				t.Fatalf("counters are not precision-safe decimal strings: %s %v", encoded, err)
			}
			if len(values) != 25 {
				t.Fatalf("lost fields: %s", encoded)
			}
			for i, name := range names {
				want := uint64(i + 1)
				if i == 2 {
					want = maximum
				}
				if values[name] != strconv.FormatUint(want, 10) {
					t.Fatalf("%d-bit %s: got %s, want %d", bits, name, values[name], want)
				}
			}
			if got := Clone(*counters); !reflect.DeepEqual(got, *counters) {
				t.Fatal("snapshot cloning lost counter precision")
			}
			base, err := decodeInterfaceCounters(counterFixture(bits, 23, order), bits, order)
			if err != nil || base.RxNoHandler != nil || base.RxOtherhostDropped != nil {
				t.Fatalf("missing extension counters fabricated: %+v %v", base, err)
			}
			zero, err := decodeInterfaceCounters(make([]byte, 25*(bits/8)), bits, order)
			if err != nil || zero.RxNoHandler == nil || *zero.RxNoHandler != 0 {
				t.Fatal("real optional zero not preserved")
			}
			for _, length := range []int{0, 23*(bits/8) - 1, 23*(bits/8) + 1} {
				if _, err := decodeInterfaceCounters(make([]byte, length), bits, order); err == nil {
					t.Fatalf("truncated encoding accepted: %d bits / %d bytes", bits, length)
				}
			}
		}
	}
	if _, err := decodeInterfaceCounters(nil, 16, binary.LittleEndian); err == nil {
		t.Fatal("invalid width accepted")
	}
	if _, err := decodeInterfaceCounters(make([]byte, 184), 64, nil); err == nil {
		t.Fatal("nil byte order accepted")
	}
}

func TestProtocolStatisticsParsing(t *testing.T) {
	data := "\nIp: Forwarding DefaultTTL InReceives\nIp: 2 64 18446744073709551615\n" +
		"Tcp: MaxConn ActiveOpens CurrEstab RetransSegs\nTcp: -1 9007199254740993 4 12\n" +
		"Udp: InDatagrams OutDatagrams InErrors\nUdp: 10 20 0\n"
	groups, err := parseProtocolStatistics(data, false)
	if err != nil || groups["Ip"]["InReceives"] != "18446744073709551615" || groups["Tcp"]["MaxConn"] != "-1" ||
		groups["Tcp"]["ActiveOpens"] != "9007199254740993" || groups["Tcp"]["CurrEstab"] != "4" || groups["Udp"]["OutDatagrams"] != "20" {
		t.Fatalf("%+v %v", groups, err)
	}
	ipv6, err := parseProtocolStatistics("Ip6InReceives 0\nUdp6OutDatagrams\t9007199254740993\n", true)
	if err != nil || ipv6["IPv6"]["Ip6InReceives"] != "0" || ipv6["IPv6"]["Udp6OutDatagrams"] != "9007199254740993" {
		t.Fatalf("%+v %v", ipv6, err)
	}
	future, err := parseProtocolStatistics("FutureProto: NewCounter\nFutureProto: 1\n", false)
	if err != nil || future["FutureProto"]["NewCounter"] != "1" {
		t.Fatal("unknown valid kernel fields were dropped", err)
	}
}

func TestProtocolStatisticsRejectMalformedSources(t *testing.T) {
	for _, input := range []string{
		"", " \n", "Tcp: A\n", "Tcp: A\nUdp: 1\n", "Tcp A\nTcp 1\n", "Tcp: A B\nTcp: 1\n",
		"Tcp: A A\nTcp: 1 2\n", "Tcp: A\nTcp: 1\nTcp: B\nTcp: 2\n",
		"Tcp: A\nTcp: -1\n", "Tcp: MaxConn\nTcp: -2\n", "Tcp: A\nTcp: 18446744073709551616\n",
		"Tcp: A\nTcp: 01\n", "Tcp: A\nTcp: +1\n", "Tcp: A\nTcp: nope\n",
		"Tcp: A\n" + strings.Repeat("1", 129*1024),
		strings.Repeat("x", maxProtocolStatisticsBytes+1),
	} {
		if _, err := parseProtocolStatistics(input, false); err == nil {
			t.Fatalf("malformed paired source accepted: %q", input[:min(len(input), 120)])
		}
	}
	for _, input := range []string{"", "Ip6InReceives", "Ip6InReceives 1 extra", "Ip6InReceives -1", "Ip6InReceives 1\nIp6InReceives 2\n", "bad/name 1"} {
		if _, err := parseProtocolStatistics(input, true); err == nil {
			t.Fatalf("malformed IPv6 source accepted: %q", input)
		}
	}
}

func TestStatisticsAreReadOnlyAndSimulated(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	journal := &failingJournal{Journal: store}
	c := EmptyConfig()
	c.Interfaces = []Interface{{Name: "z.last", Kind: "dummy", Role: "wan", MTU: 1500}, {Name: "a.first", Kind: "dummy", Role: "lan", MTU: 1400, Up: true}}
	e := testEngine(t, journal, NewSimulator(EmptyConfig()))
	tx := submit(t, e, 0, c)
	before := e.Snapshot()
	saves := journal.calls
	for _, section := range []StatisticsSection{StatisticsAll, StatisticsInterfaces, StatisticsProtocols} {
		stats, err := e.Statistics(ctx, StatisticsQuery{Section: section})
		if err != nil || stats.Sample.Status != "simulated" || stats.Sample.Scope != "simulator" ||
			stats.Sample.StartedAt.IsZero() || stats.Sample.CollectedAt.Before(stats.Sample.StartedAt) {
			t.Fatalf("%+v %v", stats, err)
		}
		if section != StatisticsProtocols {
			if len(stats.Interfaces) != 2 || stats.Interfaces[0].Name != "a.first" {
				t.Fatalf("%+v", stats.Interfaces)
			}
			for _, link := range stats.Interfaces {
				if link.Counters != nil || link.CounterBits != 0 || link.Index != 0 || link.Status != "simulated" {
					t.Fatal("simulator invented real interface statistics")
				}
			}
			stats.Interfaces[0].Name = "mutated-copy"
		}
		if section != StatisticsInterfaces {
			for _, source := range stats.Protocols {
				if source.Status != "simulated" || source.Groups != nil {
					t.Fatal("simulator invented protocol counters")
				}
			}
		}
	}
	single, err := e.Statistics(ctx, StatisticsQuery{Section: StatisticsInterfaces, Interface: "a.first"})
	if err != nil || len(single.Interfaces) != 1 || single.Interfaces[0].MTU != 1400 {
		t.Fatalf("%+v %v", single, err)
	}
	if _, err := e.Statistics(ctx, StatisticsQuery{Section: StatisticsInterfaces, Interface: "missing"}); !errors.Is(err, ErrStatisticsInterfaceNotFound) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.Statistics(cancelled, StatisticsQuery{Section: StatisticsAll}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, query := range []StatisticsQuery{{Section: "bad"}, {Section: StatisticsProtocols, Interface: "wan"}, {Section: StatisticsInterfaces, Interface: "../escape"}} {
		if _, err := e.Statistics(ctx, query); !errors.Is(err, ErrValidation) {
			t.Fatalf("invalid query accepted: %+v %v", query, err)
		}
	}
	if journal.calls != saves || !reflect.DeepEqual(before, e.Snapshot()) || e.Snapshot().Active != tx.ID {
		t.Fatal("statistics changed durable configuration")
	}
	if _, err := e.Rollback(tx.ID, "admin"); err != nil {
		t.Fatal(err)
	}
}

type statisticsUnsupportedAdapter struct{ Adapter }

func TestStatisticsUnsupportedAdapterIsExplicit(t *testing.T) {
	e := testEngine(t, testStore(t), &statisticsUnsupportedAdapter{Adapter: NewSimulator(EmptyConfig())})
	if _, err := e.Statistics(context.Background(), StatisticsQuery{Section: StatisticsAll}); err == nil {
		t.Fatal("unsupported statistics returned success")
	}
	for _, name := range []string{"lo", "eth0.100", "veth@peer"} {
		if !validStatisticsName(name) {
			t.Fatal("valid Linux interface name rejected", name)
		}
	}
	for _, name := range []string{"", ".", "..", "bad/name", "bad:name", "bad name", "bad\x00name", strings.Repeat("a", 16)} {
		if validStatisticsName(name) {
			t.Fatal("invalid name accepted", name)
		}
	}
}

func FuzzProtocolStatistics(f *testing.F) {
	f.Add("Tcp: MaxConn ActiveOpens\nTcp: -1 1\n", false)
	f.Add("Ip6InReceives 1\n", true)
	f.Add("", false)
	f.Fuzz(func(t *testing.T, input string, ipv6 bool) {
		groups, err := parseProtocolStatistics(input, ipv6)
		if err != nil {
			return
		}
		if len(groups) == 0 {
			t.Fatal("empty source reported available")
		}
		for group, fields := range groups {
			for name, value := range fields {
				if _, err := canonicalStatisticsValue(group, name, value); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
