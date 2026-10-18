package control

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func gatewayConfig() Config {
	c := EmptyConfig()
	c.Interfaces = []Interface{{Name: "wan0", Kind: "dummy", Role: "wan", MTU: 1500, Up: true,
		Addresses: []string{"192.0.2.2/24", "2001:db8::2/64"}}}
	c.Routes = []Route{{Destination: "198.51.100.0/24", Gateway: "192.0.2.1", Interface: "wan0", Table: 10000, Metric: 100}}
	c.Rules = []Rule{{Source: "192.0.2.2/32", Table: 10000, Priority: 10000}}
	c.GatewayMonitors = []GatewayMonitor{{Name: "wan1", Enabled: true, Interface: "wan0", SourceAddress: "192.0.2.2",
		Gateway: "192.0.2.1", Target: "198.51.100.10", RoutingTable: 10000}}
	c.Normalize()
	return c
}

func TestGatewayValidationAndNormalization(t *testing.T) {
	c := gatewayConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	m := c.GatewayMonitors[0]
	if m.ProbeIntervalMS != 1000 || m.LossTimeoutMS != 2000 || m.WindowMS != 30000 ||
		m.LatencyThresholdMS != 150 || m.LossThresholdPercent != 20 || m.FailureHoldMS != 3000 || m.RecoveryHoldMS != 5000 {
		t.Fatalf("unexpected defaults: %+v", m)
	}
	cases := map[string]func(*Config){
		"missing source":    func(c *Config) { c.GatewayMonitors[0].SourceAddress = "192.0.2.3" },
		"down interface":    func(c *Config) { c.Interfaces[0].Up = false },
		"missing interface": func(c *Config) { c.GatewayMonitors[0].Interface = "missing" },
		"mixed families":    func(c *Config) { c.GatewayMonitors[0].Target = "2001:db8::10" },
		"self target":       func(c *Config) { c.GatewayMonitors[0].Target = "192.0.2.2" },
		"self gateway": func(c *Config) {
			c.GatewayMonitors[0].Enabled = false
			c.GatewayMonitors[0].Gateway = c.GatewayMonitors[0].SourceAddress
		},
		"hostname":      func(c *Config) { c.GatewayMonitors[0].Target = "example.invalid" },
		"unspecified":   func(c *Config) { c.GatewayMonitors[0].Gateway = "0.0.0.0" },
		"mapped":        func(c *Config) { c.GatewayMonitors[0].Target = "::ffff:198.51.100.10" },
		"zone":          func(c *Config) { c.GatewayMonitors[0].Target = "fe80::1%wan0" },
		"no route":      func(c *Config) { c.Routes = nil },
		"wrong gateway": func(c *Config) { c.Routes[0].Gateway = "192.0.2.3" },
		"no rule":       func(c *Config) { c.Rules = nil },
		"table":         func(c *Config) { c.GatewayMonitors[0].RoutingTable = 254 },
		"probe flood":   func(c *Config) { c.GatewayMonitors[0].ProbeIntervalMS = 1 },
		"outstanding":   func(c *Config) { c.GatewayMonitors[0].LossTimeoutMS = 20000 },
		"short window":  func(c *Config) { c.GatewayMonitors[0].WindowMS = 3000 },
		"memory bound": func(c *Config) {
			c.GatewayMonitors[0].ProbeIntervalMS = 100
			c.GatewayMonitors[0].LossTimeoutMS = 200
			c.GatewayMonitors[0].WindowMS = 300000
		},
		"loss threshold": func(c *Config) { c.GatewayMonitors[0].LossThresholdPercent = 101 },
		"hold":           func(c *Config) { c.GatewayMonitors[0].RecoveryHoldMS = -1 },
		"duplicates":     func(c *Config) { c.GatewayMonitors = append(c.GatewayMonitors, c.GatewayMonitors[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			next := Clone(c)
			mutate(&next)
			if err := next.Validate(); err == nil {
				t.Fatal("invalid monitor accepted")
			}
		})
	}
	c.GatewayMonitors[0].Enabled = false
	c.Interfaces, c.Routes, c.Rules = nil, nil, nil
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled monitor cannot retain valid settings: %v", err)
	}
	v6 := gatewayConfig()
	v6.GatewayMonitors[0].SourceAddress = "2001:db8::2"
	v6.GatewayMonitors[0].Gateway = "fe80::1"
	v6.GatewayMonitors[0].Target = "2001:db8:1::10"
	v6.Routes[0].Destination, v6.Routes[0].Gateway = "2001:db8:1::/64", "fe80::1"
	v6.Rules[0].Source = "2001:db8::2/128"
	if err := v6.Validate(); err != nil {
		t.Fatalf("dual-stack/link-local gateway validation: %v", err)
	}
	empty := EmptyConfig()
	wire, err := json.Marshal(empty)
	if err != nil || !strings.Contains(string(wire), `"gateway_monitors":[]`) {
		t.Fatalf("empty monitor shape: %s %v", wire, err)
	}
}

func smallGatewayMonitor() GatewayMonitor {
	m := gatewayConfig().GatewayMonitors[0]
	m.ProbeIntervalMS, m.LossTimeoutMS, m.WindowMS = 100, 200, 1000
	m.FailureHoldMS, m.RecoveryHoldMS = 100, 100
	return m
}

func TestGatewayWindowBoundsAndRealZero(t *testing.T) {
	c := gatewayConfig()
	m := &c.GatewayMonitors[0]
	m.ProbeIntervalMS, m.LossTimeoutMS, m.WindowMS = 100, 200, 102400
	if err := c.Validate(); err != nil {
		t.Fatalf("1024-probe window rejected: %v", err)
	}
	m.WindowMS++
	if err := c.Validate(); err == nil {
		t.Fatal("window exceeding 1024 probe intervals accepted")
	}
	g := newGatewayWindow(smallGatewayMonitor(), time.Unix(1000, 0))
	g.sent(1, time.Unix(1000, 0).Add(500*time.Millisecond))
	g.reply(1, time.Unix(1000, 0).Add(500*time.Millisecond))
	s := g.sample(time.Unix(1001, 0))
	if s.RTTAvgMS == nil || *s.RTTAvgMS != 0 || s.LossPercent == nil || *s.LossPercent != 0 || s.RTTVariationMS != nil {
		t.Fatalf("real zero RTT confused with missing measurements: %+v", s)
	}
}

func TestGatewayMeasurementsExactValues(t *testing.T) {
	base := time.Unix(1000, 0)
	g := newGatewayWindow(smallGatewayMonitor(), base)
	for i := 0; i < 6; i++ {
		g.sent(uint64(i+1), base.Add(time.Duration(i)*100*time.Millisecond))
	}
	g.sent(7, base.Add(990*time.Millisecond))
	for _, r := range []struct {
		seq uint64
		rtt int
	}{{6, 40}, {1, 10}, {5, 60}, {2, 30}, {4, 20}} {
		g.reply(r.seq, base.Add(time.Duration(r.seq-1)*100*time.Millisecond+time.Duration(r.rtt)*time.Millisecond))
	}
	g.reply(1, base.Add(90*time.Millisecond))
	g.reply(3, base.Add(500*time.Millisecond))
	g.reply(999, base.Add(500*time.Millisecond))
	s := g.sample(base.Add(time.Second))
	if s.Sent != 7 || s.Received != 5 || s.Lost != 1 || s.Pending != 1 || s.VariationPairs != 3 {
		t.Fatalf("incorrect accounting or variation across loss: %+v", s)
	}
	for name, pair := range map[string]struct {
		got  *float64
		want float64
	}{
		"loss": {s.LossPercent, 100.0 / 6}, "average": {s.RTTAvgMS, 32}, "min": {s.RTTMinMS, 10},
		"max": {s.RTTMaxMS, 60}, "stddev": {s.RTTStddevMS, math.Sqrt(296)}, "p50": {s.RTTP50MS, 30},
		"p95": {s.RTTP95MS, 60}, "variation": {s.RTTVariationMS, 80.0 / 3},
	} {
		if pair.got == nil || math.Abs(*pair.got-pair.want) > 1e-9 {
			t.Fatalf("%s: got %v, expected %.12f", name, pair.got, pair.want)
		}
	}
	s = g.sample(base.Add(3 * time.Second))
	if s.Sent != 0 || s.RTTAvgMS != nil || s.LossPercent != nil || s.RTTVariationMS != nil ||
		s.SampleStatus != "unavailable" || s.Health != "unknown" || s.LastSuccessAt == nil {
		t.Fatalf("empty window synthesized zero/healthy data: %+v", s)
	}
}

func TestGatewayWarmupHealthAndRecoveryHolds(t *testing.T) {
	base := time.Unix(1000, 0)
	g := newGatewayWindow(smallGatewayMonitor(), base)
	g.sent(1, base.Add(500*time.Millisecond))
	if s := g.sample(base.Add(900 * time.Millisecond)); s.Health != "unknown" || s.SampleStatus != "warming_up" {
		t.Fatal("startup loss was classified before warmup")
	}
	g.sample(base.Add(time.Second))
	if s := g.sample(base.Add(1099 * time.Millisecond)); s.Health != "unknown" {
		t.Fatal("failure hold was not respected")
	}
	if s := g.sample(base.Add(1100 * time.Millisecond)); s.Health != "down" || s.RTTAvgMS != nil || *s.LossPercent != 100 {
		t.Fatalf("complete loss classified incorrectly: %+v", s)
	}
	g.sent(2, base.Add(1510*time.Millisecond))
	g.reply(2, base.Add(1520*time.Millisecond))
	if s := g.sample(base.Add(1530 * time.Millisecond)); s.Health != "down" {
		t.Fatal("recovery bypassed hold")
	}
	if s := g.sample(base.Add(1630 * time.Millisecond)); s.Health != "up" || s.HealthChangedAt == nil {
		t.Fatalf("sustained recovery not applied: %+v", s)
	}
	g.config.RTTVariationThresholdMS = 5
	g.sent(3, base.Add(1700*time.Millisecond))
	g.reply(3, base.Add(1730*time.Millisecond))
	g.sample(base.Add(1740 * time.Millisecond))
	if s := g.sample(base.Add(1840 * time.Millisecond)); s.Health != "degraded" || *s.RTTVariationMS != 20 {
		t.Fatalf("variation threshold not applied: %+v", s)
	}
}

func TestGatewaySimulatorSummaryStatus(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		name := "empty"
		if disabled {
			name = "disabled"
		}
		t.Run(name, func(t *testing.T) {
			e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
			wantCount := 0
			if disabled {
				c := gatewayConfig()
				c.GatewayMonitors[0].Enabled = false
				tx := submit(t, e, 0, c)
				if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
					t.Fatal(err)
				}
				wantCount = 1
			}
			stats, err := e.Statistics(context.Background(), StatisticsQuery{Section: StatisticsGateways})
			if err != nil || stats.Sample.Status != "simulated" || len(stats.Gateways) != wantCount {
				t.Fatalf("simulator summary implies native measurements: %+v %v", stats, err)
			}
			if disabled && (stats.Gateways[0].SampleStatus != "disabled" ||
				stats.Gateways[0].Health != "unknown" || stats.Gateways[0].RTTAvgMS != nil) {
				t.Fatalf("disabled monitor fabricated measurements: %+v", stats.Gateways[0])
			}
		})
	}
}

func TestGatewayPersistenceRollbackRestoreAndSimulator(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	c := gatewayConfig()
	tx := submit(t, e, 0, c)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	next := Clone(c)
	next.GatewayMonitors[0].Enabled = false
	tx = submit(t, e, 1, next)
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	restarted := testEngine(t, store, NewSimulator(c))
	stats, err := restarted.Statistics(context.Background(), StatisticsQuery{Section: StatisticsGateways, Monitor: "wan1"})
	if err != nil || len(stats.Gateways) != 1 || stats.Gateways[0].ProcessState != "simulated" ||
		stats.Gateways[0].Health != "unknown" || stats.Gateways[0].RTTAvgMS != nil {
		t.Fatalf("simulator fabricated probes or lost settings: %+v %v", stats, err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.Desired.GatewayMonitors) != 1 || !loaded.Desired.GatewayMonitors[0].Enabled {
		t.Fatalf("monitor settings not durable: %+v %v", loaded.Desired.GatewayMonitors, err)
	}
	tx = submit(t, restarted, 1, next)
	if _, err := restarted.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	tx, err = restarted.Restore(context.Background(), "test", 1, RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if err != nil || !tx.Candidate.GatewayMonitors[0].Enabled {
		t.Fatalf("revision restore lost monitors: %+v %v", tx, err)
	}
	if _, err := restarted.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
}
