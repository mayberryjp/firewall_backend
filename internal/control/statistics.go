package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrStatisticsInterfaceNotFound = errors.New("statistics interface not found")
var ErrGatewayMonitorNotFound = errors.New("gateway monitor not found")

type StatisticsSection string

const (
	StatisticsAll        StatisticsSection = "all"
	StatisticsInterfaces StatisticsSection = "interfaces"
	StatisticsProtocols  StatisticsSection = "protocols"
	StatisticsGateways   StatisticsSection = "gateways"
)

type StatisticsQuery struct {
	Section   StatisticsSection
	Interface string
	Monitor   string
}

func (q StatisticsQuery) Validate() error {
	if q.Section != StatisticsAll && q.Section != StatisticsInterfaces && q.Section != StatisticsProtocols && q.Section != StatisticsGateways {
		return fmt.Errorf("%w: unknown statistics section", ErrValidation)
	}
	if q.Interface != "" && (q.Section != StatisticsInterfaces || !validStatisticsName(q.Interface)) {
		return fmt.Errorf("%w: invalid statistics interface", ErrValidation)
	}
	if q.Monitor != "" && (q.Section != StatisticsGateways || !serviceNamePattern.MatchString(q.Monitor)) {
		return fmt.Errorf("%w: invalid statistics monitor", ErrValidation)
	}
	return nil
}

func validStatisticsName(name string) bool {
	return len(name) > 0 && len(name) <= 15 && name != "." && name != ".." && utf8.ValidString(name) && !strings.ContainsAny(name, "\x00/:\t\n\v\f\r ")
}

type StatisticsSample struct {
	Scope       string    `json:"scope"`
	StartedAt   time.Time `json:"started_at"`
	CollectedAt time.Time `json:"collected_at"`
	Status      string    `json:"status"`
}

type NetworkStatistics struct {
	Gateways   []GatewayMonitorStatistics `json:"gateways,omitempty"`
	Sample     StatisticsSample           `json:"sample"`
	Interfaces []InterfaceStatistics      `json:"interfaces"`
	Protocols  []ProtocolStatistics       `json:"protocols"`
}

type InterfaceStatistics struct {
	Name        string             `json:"name"`
	Index       int                `json:"index,omitempty"`
	Kind        string             `json:"kind"`
	Ownership   string             `json:"ownership"`
	MTU         int                `json:"mtu"`
	AdminUp     bool               `json:"admin_up"`
	OperState   string             `json:"oper_state"`
	MAC         string             `json:"mac,omitempty"`
	Status      string             `json:"status"`
	CounterBits int                `json:"counter_bits,omitempty"`
	Counters    *InterfaceCounters `json:"counters"`
	Error       string             `json:"error,omitempty"`
}

type InterfaceCounters struct {
	RxPackets          uint64  `json:"rx_packets,string"`
	TxPackets          uint64  `json:"tx_packets,string"`
	RxBytes            uint64  `json:"rx_bytes,string"`
	TxBytes            uint64  `json:"tx_bytes,string"`
	RxErrors           uint64  `json:"rx_errors,string"`
	TxErrors           uint64  `json:"tx_errors,string"`
	RxDropped          uint64  `json:"rx_dropped,string"`
	TxDropped          uint64  `json:"tx_dropped,string"`
	Multicast          uint64  `json:"multicast,string"`
	Collisions         uint64  `json:"collisions,string"`
	RxLengthErrors     uint64  `json:"rx_length_errors,string"`
	RxOverErrors       uint64  `json:"rx_over_errors,string"`
	RxCRCErrors        uint64  `json:"rx_crc_errors,string"`
	RxFrameErrors      uint64  `json:"rx_frame_errors,string"`
	RxFIFOErrors       uint64  `json:"rx_fifo_errors,string"`
	RxMissedErrors     uint64  `json:"rx_missed_errors,string"`
	TxAbortedErrors    uint64  `json:"tx_aborted_errors,string"`
	TxCarrierErrors    uint64  `json:"tx_carrier_errors,string"`
	TxFIFOErrors       uint64  `json:"tx_fifo_errors,string"`
	TxHeartbeatErrors  uint64  `json:"tx_heartbeat_errors,string"`
	TxWindowErrors     uint64  `json:"tx_window_errors,string"`
	RxCompressed       uint64  `json:"rx_compressed,string"`
	TxCompressed       uint64  `json:"tx_compressed,string"`
	RxNoHandler        *uint64 `json:"rx_nohandler,omitempty,string"`
	RxOtherhostDropped *uint64 `json:"rx_otherhost_dropped,omitempty,string"`
}

type ProtocolStatistics struct {
	Name   string                       `json:"name"`
	Status string                       `json:"status"`
	Groups map[string]map[string]string `json:"groups"`
	Error  string                       `json:"error,omitempty"`
}

type StatisticsAdapter interface {
	Statistics(context.Context, StatisticsQuery, Config) (NetworkStatistics, error)
}

type GatewayStatisticsAdapter interface {
	GatewayStatistics(context.Context, Config) ([]GatewayMonitorStatistics, error)
}

func newNetworkStatistics(scope string) NetworkStatistics {
	return NetworkStatistics{Sample: StatisticsSample{Scope: scope, StartedAt: time.Now().UTC(), Status: "available"},
		Interfaces: []InterfaceStatistics{}, Protocols: []ProtocolStatistics{}}
}

func (e *Engine) Statistics(ctx context.Context, query StatisticsQuery) (NetworkStatistics, error) {
	if err := query.Validate(); err != nil {
		return NetworkStatistics{}, err
	}
	if query.Section == StatisticsGateways {
		e.mu.Lock()
		expected, scope := Clone(e.runtimeConfig()), e.adapter.Scope()
		adapter, ok := e.adapter.(GatewayStatisticsAdapter)
		e.mu.Unlock()
		if !ok {
			return NetworkStatistics{}, fmt.Errorf("adapter does not expose gateway statistics")
		}
		gateways, err := adapter.GatewayStatistics(ctx, expected)
		if err != nil {
			return NetworkStatistics{}, err
		}
		result := newNetworkStatistics(scope)
		if scope == "simulator" {
			result.Sample.Status = "simulated"
		}
		result.Gateways = []GatewayMonitorStatistics{}
		for _, gateway := range gateways {
			if query.Monitor != "" && gateway.Name != query.Monitor {
				continue
			}
			result.Gateways = append(result.Gateways, gateway)
			if gateway.SampleStatus == "simulated" {
				result.Sample.Status = "simulated"
			} else if gateway.SampleStatus != "available" && gateway.SampleStatus != "disabled" {
				result.Sample.Status = "partial"
			}
		}
		if query.Monitor != "" && len(result.Gateways) == 0 {
			return NetworkStatistics{}, ErrGatewayMonitorNotFound
		}
		result.Sample.CollectedAt = time.Now().UTC()
		return Clone(result), ctx.Err()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return NetworkStatistics{}, err
	}
	adapter, ok := e.adapter.(StatisticsAdapter)
	if !ok {
		return NetworkStatistics{}, fmt.Errorf("adapter does not expose network statistics")
	}
	result, err := adapter.Statistics(ctx, query, Clone(e.runtimeConfig()))
	if err != nil {
		return NetworkStatistics{}, err
	}
	return Clone(result), ctx.Err()
}

func (s *Simulator) Statistics(ctx context.Context, query StatisticsQuery, _ Config) (NetworkStatistics, error) {
	if err := query.Validate(); err != nil {
		return NetworkStatistics{}, err
	}
	if err := ctx.Err(); err != nil {
		return NetworkStatistics{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := newNetworkStatistics(s.Scope())
	result.Sample.Status = "simulated"
	if query.Section == StatisticsAll {
		result.Gateways = inactiveGatewayStatistics(s.state.GatewayMonitors, "simulated")
	}
	if query.Section != StatisticsProtocols {
		for _, link := range s.state.Interfaces {
			if query.Interface != "" && link.Name != query.Interface {
				continue
			}
			result.Interfaces = append(result.Interfaces, InterfaceStatistics{Name: link.Name, Kind: link.Kind,
				Ownership: "managed", MTU: link.MTU, AdminUp: link.Up, OperState: "unknown", Status: "simulated"})
		}
		if query.Interface != "" && len(result.Interfaces) == 0 {
			return NetworkStatistics{}, fmt.Errorf("%w: %s", ErrStatisticsInterfaceNotFound, query.Interface)
		}
	}
	if query.Section != StatisticsInterfaces {
		for _, name := range []string{"snmp", "netstat", "snmp6"} {
			result.Protocols = append(result.Protocols, ProtocolStatistics{Name: name, Status: "simulated"})
		}
	}
	slices.SortFunc(result.Interfaces, func(a, b InterfaceStatistics) int { return strings.Compare(a.Name, b.Name) })
	result.Sample.CollectedAt = time.Now().UTC()
	return result, ctx.Err()
}

func decodeInterfaceCounters(data []byte, bits int, order binary.ByteOrder) (*InterfaceCounters, error) {
	if (bits != 32 && bits != 64) || order == nil {
		return nil, fmt.Errorf("invalid interface counter encoding")
	}
	size := bits / 8
	c := &InterfaceCounters{}
	fields := []*uint64{&c.RxPackets, &c.TxPackets, &c.RxBytes, &c.TxBytes, &c.RxErrors, &c.TxErrors, &c.RxDropped, &c.TxDropped, &c.Multicast, &c.Collisions,
		&c.RxLengthErrors, &c.RxOverErrors, &c.RxCRCErrors, &c.RxFrameErrors, &c.RxFIFOErrors, &c.RxMissedErrors,
		&c.TxAbortedErrors, &c.TxCarrierErrors, &c.TxFIFOErrors, &c.TxHeartbeatErrors, &c.TxWindowErrors, &c.RxCompressed, &c.TxCompressed}
	if len(data) < len(fields)*size || len(data)%size != 0 {
		return nil, fmt.Errorf("truncated %d-bit interface statistics", bits)
	}
	read := func(i int) uint64 {
		if bits == 32 {
			return uint64(order.Uint32(data[i*size:]))
		}
		return order.Uint64(data[i*size:])
	}
	for i, field := range fields {
		*field = read(i)
	}
	if len(data) >= 24*size {
		value := read(23)
		c.RxNoHandler = &value
	}
	if len(data) >= 25*size {
		value := read(24)
		c.RxOtherhostDropped = &value
	}
	return c, nil
}
