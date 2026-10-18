package control

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"
)

type GatewayMonitor struct {
	Name                    string `json:"name"`
	Enabled                 bool   `json:"enabled"`
	Interface               string `json:"interface"`
	SourceAddress           string `json:"source_address"`
	Gateway                 string `json:"gateway"`
	Target                  string `json:"target"`
	RoutingTable            int    `json:"routing_table"`
	ProbeIntervalMS         int    `json:"probe_interval_ms"`
	LossTimeoutMS           int    `json:"loss_timeout_ms"`
	WindowMS                int    `json:"window_ms"`
	LatencyThresholdMS      int    `json:"latency_threshold_ms"`
	LossThresholdPercent    int    `json:"loss_threshold_percent"`
	RTTVariationThresholdMS int    `json:"rtt_variation_threshold_ms"`
	FailureHoldMS           int    `json:"failure_hold_ms"`
	RecoveryHoldMS          int    `json:"recovery_hold_ms"`
}

func (m *GatewayMonitor) normalize() {
	defaults := []struct {
		value    *int
		fallback int
	}{
		{&m.ProbeIntervalMS, 1000}, {&m.LossTimeoutMS, 2000}, {&m.WindowMS, 30000},
		{&m.LatencyThresholdMS, 150}, {&m.LossThresholdPercent, 20},
		{&m.FailureHoldMS, 3000}, {&m.RecoveryHoldMS, 5000},
	}
	for _, d := range defaults {
		if *d.value == 0 {
			*d.value = d.fallback
		}
	}
}

func monitorAddress(value string, linkLocal bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || a.Is4In6() || a.Zone() != "" || a.String() != value ||
		(!a.IsGlobalUnicast() && !(linkLocal && a.Is6() && a.IsLinkLocalUnicast())) {
		return netip.Addr{}, fmt.Errorf("invalid canonical unicast monitor address %q", value)
	}
	return a, nil
}

func validateGatewayMonitors(c Config) error {
	if len(c.GatewayMonitors) > 64 {
		return fmt.Errorf("at most 64 gateway monitors are supported")
	}
	names := map[string]bool{}
	for _, original := range c.GatewayMonitors {
		m := original
		m.normalize()
		if !serviceNamePattern.MatchString(m.Name) || names[m.Name] || !validInterfaceName(m.Interface) {
			return fmt.Errorf("invalid or duplicate gateway monitor name/interface %q", m.Name)
		}
		names[m.Name] = true
		source, err := monitorAddress(m.SourceAddress, false)
		if err != nil {
			return err
		}
		gateway, err := monitorAddress(m.Gateway, true)
		if err != nil {
			return err
		}
		target, err := monitorAddress(m.Target, true)
		if err != nil {
			return err
		}
		if source.Is4() != gateway.Is4() || source.Is4() != target.Is4() || source == target || source == gateway ||
			m.RoutingTable < 10000 || m.RoutingTable > 19999 {
			return fmt.Errorf("monitor %s requires matching address families, a remote target, and table 10000..19999", m.Name)
		}
		if m.ProbeIntervalMS < 100 || m.ProbeIntervalMS > 60000 ||
			m.LossTimeoutMS < 100 || m.LossTimeoutMS > 60000 || m.LossTimeoutMS > 10*m.ProbeIntervalMS ||
			m.WindowMS < 1000 || m.WindowMS > 300000 || m.WindowMS < 2*m.LossTimeoutMS ||
			m.WindowMS < 3*m.ProbeIntervalMS || m.WindowMS > 1024*m.ProbeIntervalMS {
			return fmt.Errorf("monitor %s has invalid interval/timeout/window bounds", m.Name)
		}
		if m.LatencyThresholdMS < 1 || m.LatencyThresholdMS > 60000 ||
			m.LossThresholdPercent < 1 || m.LossThresholdPercent > 100 ||
			m.RTTVariationThresholdMS < 0 || m.RTTVariationThresholdMS > 60000 ||
			m.FailureHoldMS < 100 || m.FailureHoldMS > 60000 ||
			m.RecoveryHoldMS < 100 || m.RecoveryHoldMS > 60000 {
			return fmt.Errorf("monitor %s has invalid health thresholds/holds", m.Name)
		}
		if !m.Enabled {
			continue
		}
		found := false
		for _, link := range c.Interfaces {
			if link.Name != m.Interface || !link.Up {
				continue
			}
			for _, text := range link.Addresses {
				if p, err := netip.ParsePrefix(text); err == nil && p.Addr() == source {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("monitor %s requires its source address on an up managed interface", m.Name)
		}
		routeFound, ruleFound := false, false
		for _, r := range c.Routes {
			p, err := netip.ParsePrefix(r.Destination)
			if err == nil && p.Contains(target) && r.Interface == m.Interface && r.Table == m.RoutingTable &&
				(r.Gateway == m.Gateway || (target == gateway && r.Gateway == "")) {
				routeFound = true
			}
		}
		for _, r := range c.Rules {
			p, err := netip.ParsePrefix(r.Source)
			if err == nil && p.Contains(source) && r.Table == m.RoutingTable {
				ruleFound = true
			}
		}
		if !routeFound || !ruleFound {
			return fmt.Errorf("monitor %s requires an explicit matching route and source-policy rule", m.Name)
		}
	}
	return nil
}

type GatewayMonitorStatistics struct {
	Name            string     `json:"name"`
	ProcessState    string     `json:"process_state"`
	SampleStatus    string     `json:"sample_status"`
	Health          string     `json:"health"`
	StartedAt       *time.Time `json:"started_at"`
	CollectedAt     *time.Time `json:"collected_at"`
	HealthChangedAt *time.Time `json:"health_changed_at"`
	LastSuccessAt   *time.Time `json:"last_success_at"`
	Sent            int        `json:"sent"`
	Received        int        `json:"received"`
	Lost            int        `json:"lost"`
	Pending         int        `json:"pending"`
	VariationPairs  int        `json:"variation_pairs"`
	LossPercent     *float64   `json:"loss_percent"`
	RTTMinMS        *float64   `json:"rtt_min_ms"`
	RTTMaxMS        *float64   `json:"rtt_max_ms"`
	RTTAvgMS        *float64   `json:"rtt_avg_ms"`
	RTTStddevMS     *float64   `json:"rtt_stddev_ms"`
	RTTP50MS        *float64   `json:"rtt_p50_ms"`
	RTTP95MS        *float64   `json:"rtt_p95_ms"`
	RTTVariationMS  *float64   `json:"rtt_variation_ms"`
	Error           string     `json:"error,omitempty"`
}

type gatewayProbe struct {
	sequence uint64
	sent     time.Time
	received *time.Time
}

type gatewayWindow struct {
	config         GatewayMonitor
	started        time.Time
	probes         []gatewayProbe
	lastSuccess    *time.Time
	health         string
	changed        *time.Time
	candidate      string
	candidateSince time.Time
}

func newGatewayWindow(config GatewayMonitor, started time.Time) *gatewayWindow {
	return &gatewayWindow{config: config, started: started, health: "unknown"}
}

func gatewayTime(t time.Time) *time.Time {
	v := t.UTC()
	return &v
}

func gatewayNumber(v float64) *float64 { return &v }

func (g *gatewayWindow) sent(sequence uint64, now time.Time) {
	g.probes = append(g.probes, gatewayProbe{sequence: sequence, sent: now})
}

func (g *gatewayWindow) reply(sequence uint64, received time.Time) {
	for i := len(g.probes) - 1; i >= 0; i-- {
		p := &g.probes[i]
		if p.sequence == sequence {
			if p.received == nil && !received.Before(p.sent) &&
				received.Sub(p.sent) <= time.Duration(g.config.LossTimeoutMS)*time.Millisecond {
				p.received = &received
				if g.lastSuccess == nil || received.After(*g.lastSuccess) {
					g.lastSuccess = &received
				}
			}
			return
		}
	}
}

func (g *gatewayWindow) sample(now time.Time) GatewayMonitorStatistics {
	cutoff := now.Add(-time.Duration(g.config.WindowMS) * time.Millisecond)
	first := 0
	for first < len(g.probes) && g.probes[first].sent.Before(cutoff) {
		first++
	}
	g.probes = slices.Delete(g.probes, 0, first)
	result := GatewayMonitorStatistics{Name: g.config.Name, ProcessState: "running",
		SampleStatus: "warming_up", Health: "unknown", StartedAt: gatewayTime(g.started),
		CollectedAt: gatewayTime(now), Sent: len(g.probes)}
	if g.lastSuccess != nil {
		result.LastSuccessAt = gatewayTime(*g.lastSuccess)
	}
	var values []float64
	var sum, variation float64
	var previous *gatewayProbe
	for i := range g.probes {
		p := &g.probes[i]
		if p.received != nil {
			rtt := float64(p.received.Sub(p.sent)) / float64(time.Millisecond)
			values = append(values, rtt)
			sum += rtt
			result.Received++
			if previous != nil && previous.received != nil && previous.sequence+1 == p.sequence {
				old := float64(previous.received.Sub(previous.sent)) / float64(time.Millisecond)
				variation += math.Abs(rtt - old)
				result.VariationPairs++
			}
		} else if now.Sub(p.sent) >= time.Duration(g.config.LossTimeoutMS)*time.Millisecond {
			result.Lost++
		} else {
			result.Pending++
		}
		previous = p
	}
	if completed := result.Received + result.Lost; completed > 0 {
		result.LossPercent = gatewayNumber(float64(result.Lost) * 100 / float64(completed))
	}
	if len(values) > 0 {
		avg := sum / float64(len(values))
		var squared float64
		for _, value := range values {
			squared += (value - avg) * (value - avg)
		}
		slices.Sort(values)
		result.RTTMinMS, result.RTTMaxMS, result.RTTAvgMS = gatewayNumber(values[0]), gatewayNumber(values[len(values)-1]), gatewayNumber(avg)
		result.RTTStddevMS = gatewayNumber(math.Sqrt(squared / float64(len(values))))
		result.RTTP50MS = gatewayNumber(values[int(math.Ceil(0.50*float64(len(values))))-1])
		result.RTTP95MS = gatewayNumber(values[int(math.Ceil(0.95*float64(len(values))))-1])
	}
	if result.VariationPairs > 0 {
		result.RTTVariationMS = gatewayNumber(variation / float64(result.VariationPairs))
	}
	if now.Sub(g.started) >= time.Duration(g.config.WindowMS)*time.Millisecond && result.LossPercent != nil {
		result.SampleStatus = "available"
		candidate := "up"
		if *result.LossPercent == 100 {
			candidate = "down"
		} else if *result.LossPercent >= float64(g.config.LossThresholdPercent) ||
			(result.RTTAvgMS != nil && *result.RTTAvgMS >= float64(g.config.LatencyThresholdMS)) ||
			(g.config.RTTVariationThresholdMS > 0 && result.RTTVariationMS != nil &&
				*result.RTTVariationMS >= float64(g.config.RTTVariationThresholdMS)) {
			candidate = "degraded"
		}
		if candidate != g.candidate {
			g.candidate, g.candidateSince = candidate, now
		}
		rank := map[string]int{"unknown": -1, "up": 0, "degraded": 1, "down": 2}
		hold := g.config.FailureHoldMS
		if rank[candidate] < rank[g.health] || candidate == "up" {
			hold = g.config.RecoveryHoldMS
		}
		if candidate != g.health && now.Sub(g.candidateSince) >= time.Duration(hold)*time.Millisecond {
			g.health, g.changed = candidate, gatewayTime(now)
		}
		result.Health, result.HealthChangedAt = g.health, g.changed
	} else {
		g.health, g.candidate = "unknown", ""
		if now.Sub(g.started) >= time.Duration(g.config.WindowMS)*time.Millisecond {
			result.SampleStatus, result.Error = "unavailable", "no completed probes in the measurement window"
		}
	}
	return result
}

func inactiveGatewayStatistics(monitors []GatewayMonitor, enabledState string) []GatewayMonitorStatistics {
	result := make([]GatewayMonitorStatistics, 0, len(monitors))
	for _, m := range monitors {
		state := "disabled"
		if m.Enabled {
			state = enabledState
		}
		result = append(result, GatewayMonitorStatistics{Name: m.Name, ProcessState: state, SampleStatus: state, Health: "unknown"})
	}
	return result
}
