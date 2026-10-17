package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func vlanConfig() Config {
	c := EmptyConfig()
	c.Interfaces = []Interface{
		{Name: "a.inner", Kind: "vlan", Role: "lan", MTU: 1400, Up: true, VLAN: &VLAN{Parent: "z.outer", ID: 200}},
		{Name: "z.outer", Kind: "vlan", Role: "wan", MTU: 1500, Up: true, VLAN: &VLAN{Parent: "uplink", ID: 100}},
	}
	c.Normalize()
	return c
}

func flowConfig() SoftflowdConfig {
	return SoftflowdConfig{Name: "office", Enabled: true, Interface: "uplink.100", Collector: "192.0.2.50:2055",
		ExportVersion: 10, SamplingRate: 100, MaxFlows: 65536, Snaplen: 256, Timeouts: map[string]int{"general": 60, "tcp": 300, "icmp": 30}}
}

func TestVLANValidationAndDependencyOrdering(t *testing.T) {
	c := vlanConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	ordered, err := orderedInterfaces(c.Interfaces)
	if err != nil || ordered[0].Name != "z.outer" || ordered[1].Name != "a.inner" {
		t.Fatalf("incorrect order: %+v %v", ordered, err)
	}
	for _, id := range []int{1, 4094} {
		next := Clone(c)
		next.Interfaces[0].VLAN.ID = id
		if err := next.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	tests := map[string]func(*Config){
		"missing-settings": func(c *Config) { c.Interfaces[0].VLAN = nil },
		"id-zero":          func(c *Config) { c.Interfaces[0].VLAN.ID = 0 },
		"id-reserved":      func(c *Config) { c.Interfaces[0].VLAN.ID = 4095 },
		"invalid-parent":   func(c *Config) { c.Interfaces[0].VLAN.Parent = "../parent" },
		"self-parent":      func(c *Config) { c.Interfaces[0].VLAN.Parent = c.Interfaces[0].Name },
		"cycle":            func(c *Config) { c.Interfaces[1].VLAN.Parent = c.Interfaces[0].Name },
		"oversized-mtu":    func(c *Config) { c.Interfaces[0].MTU = 1600 },
		"duplicate-id": func(c *Config) {
			c.Interfaces = append(c.Interfaces, Interface{Name: "duplicate", Kind: "vlan", Role: "lan", MTU: 1400, VLAN: &VLAN{Parent: "uplink", ID: 100}})
		},
		"settings-on-dummy": func(c *Config) { c.Interfaces[0].Kind = "dummy" },
		"wireguard-parent": func(c *Config) {
			c.Interfaces[1].Kind = "wireguard"
			c.Interfaces[1].VLAN = nil
			c.Interfaces[1].WireGuard = &WireGuard{KeyRef: "wg0", ListenPort: 51820}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			next := Clone(c)
			mutate(&next)
			if err := next.Validate(); err == nil {
				t.Fatal("invalid VLAN accepted")
			}
		})
	}
	for _, name := range []string{".", "..", "lo", "bad/name", strings.Repeat("a", 16)} {
		if validInterfaceName(name) {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
	if !validInterfaceName("eth0.100") {
		t.Fatal("dotted interface name rejected")
	}
}

func TestSoftflowdValidation(t *testing.T) {
	c := EmptyConfig()
	c.Softflowd = []SoftflowdConfig{flowConfig()}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{1, 5, 9, 10} {
		next := Clone(c)
		next.Softflowd[0].ExportVersion = version
		if err := next.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, collector := range []string{"127.0.0.1:2055", "[2001:db8::50]:4739", "[::1]:2055"} {
		next := Clone(c)
		next.Softflowd[0].Collector = collector
		if err := next.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, timeout := range softflowdTimeouts {
		next := Clone(c)
		next.Softflowd[0].Timeouts = map[string]int{timeout: 604800}
		if err := next.Validate(); err != nil {
			t.Fatal(err)
		}
		if timeout != "general" {
			next.Softflowd[0].Timeouts[timeout] = 0
			if err := next.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	tests := map[string]func(*SoftflowdConfig){
		"name":                   func(s *SoftflowdConfig) { s.Name = "../escape" },
		"interface":              func(s *SoftflowdConfig) { s.Interface = "lo" },
		"collector-dns":          func(s *SoftflowdConfig) { s.Collector = "collector.example:2055" },
		"collector-port":         func(s *SoftflowdConfig) { s.Collector = "192.0.2.1:0" },
		"collector-multicast":    func(s *SoftflowdConfig) { s.Collector = "239.1.1.1:2055" },
		"collector-unspecified":  func(s *SoftflowdConfig) { s.Collector = "0.0.0.0:2055" },
		"collector-mapped":       func(s *SoftflowdConfig) { s.Collector = "[::ffff:192.0.2.1]:2055" },
		"collector-noncanonical": func(s *SoftflowdConfig) { s.Collector = "[2001:0db8::1]:2055" },
		"version":                func(s *SoftflowdConfig) { s.ExportVersion = 8 },
		"sampling":               func(s *SoftflowdConfig) { s.SamplingRate = 0 },
		"sampling-limit":         func(s *SoftflowdConfig) { s.SamplingRate = 1000001 },
		"flows":                  func(s *SoftflowdConfig) { s.MaxFlows = 0 },
		"flows-limit":            func(s *SoftflowdConfig) { s.MaxFlows = 1000001 },
		"snaplen":                func(s *SoftflowdConfig) { s.Snaplen = 63 },
		"snaplen-limit":          func(s *SoftflowdConfig) { s.Snaplen = 65536 },
		"filter-newline":         func(s *SoftflowdConfig) { s.CaptureFilter = "tcp\nudp" },
		"filter-nul":             func(s *SoftflowdConfig) { s.CaptureFilter = "tcp\x00" },
		"filter-limit":           func(s *SoftflowdConfig) { s.CaptureFilter = strings.Repeat("a", 4097) },
		"timeout-name":           func(s *SoftflowdConfig) { s.Timeouts["arbitrary"] = 1 },
		"timeout-negative":       func(s *SoftflowdConfig) { s.Timeouts["tcp"] = -1 },
		"timeout-limit":          func(s *SoftflowdConfig) { s.Timeouts["udp"] = 604801 },
		"general-zero":           func(s *SoftflowdConfig) { s.Timeouts["general"] = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			next := Clone(c)
			mutate(&next.Softflowd[0])
			if err := next.Validate(); err == nil {
				t.Fatal("invalid service accepted")
			}
		})
	}
	duplicate := Clone(c)
	duplicate.Softflowd = append(duplicate.Softflowd, flowConfig())
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate instance accepted")
	}
	excess := Clone(c)
	excess.Softflowd = make([]SoftflowdConfig, 17)
	if err := excess.Validate(); err == nil {
		t.Fatal("excessive instance count accepted")
	}
}

func TestSoftflowdArgumentsAreTypedAndDeterministic(t *testing.T) {
	s := flowConfig()
	s.CaptureFilter = "-i other ; $(touch unwanted)"
	args := softflowdArgs(s, "control.sock", "process.pid")
	expected := []string{"-d", "-i", "uplink.100", "-n", "192.0.2.50:2055", "-v", "10", "-P", "udp", "-s", "100", "-m", "65536", "-C", "256",
		"-c", "control.sock", "-p", "process.pid", "-N", "-t", "general=60", "-t", "icmp=30", "-t", "tcp=300", "--", s.CaptureFilter}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("unexpected arguments: %#v", args)
	}
	s.Promiscuous = true
	s.CaptureFilter = ""
	args = softflowdArgs(s, "control.sock", "process.pid")
	if slices.Contains(args, "-N") || args[len(args)-1] != "--" {
		t.Fatalf("promiscuity/filter flags: %#v", args)
	}
}

func TestVLANAndServicesHistoryRollbackAndIdentity(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	c := vlanConfig()
	c.Softflowd = []SoftflowdConfig{flowConfig()}
	c.Softflowd[0].Interface = "a.inner"
	commitConfig(t, e, c)
	next := Clone(c)
	next.Interfaces[0].VLAN.ID++
	if _, err := e.Submit(context.Background(), "admin", Request{BaseRevision: 1, ConfirmSeconds: 30, Config: next}); !errors.Is(err, ErrValidation) {
		t.Fatalf("VLAN reidentification accepted: %v", err)
	}
	if len(e.Snapshot().Transactions) != 1 {
		t.Fatal("rejected identity change persisted intent")
	}
	next = Clone(c)
	next.Softflowd[0].Enabled = false
	tx := submit(t, e, 1, next)
	runtime, err := e.Runtime(context.Background())
	if err != nil || len(runtime.Softflowd) != 1 || runtime.Softflowd[0].State != "disabled" {
		t.Fatalf("%+v %v", runtime, err)
	}
	if _, err := e.Rollback(tx.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	view, err := e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("%+v %v", view, err)
	}
	commitConfig(t, e, EmptyConfig())
	e = testEngine(t, store, NewSimulator(EmptyConfig()))
	revision, err := e.GetRevision(1)
	if err != nil || !Equal(revision.Config, c) {
		t.Fatalf("%+v %v", revision, err)
	}
	restored, err := e.Restore(context.Background(), "admin", 1, RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(context.Background(), restored.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Desired, c) {
		t.Fatalf("%+v %v", view, err)
	}
}

type runtimeTestAdapter struct {
	*Simulator
	resumed      []Config
	resumeErr    error
	reconcileErr error
}

func (a *runtimeTestAdapter) Resume(ctx context.Context, c Config) error {
	a.resumed = append(a.resumed, Clone(c))
	if a.resumeErr != nil {
		return a.resumeErr
	}
	return a.Simulator.Resume(ctx, c)
}

func (a *runtimeTestAdapter) Reconcile(ctx context.Context, c Config) error {
	if a.reconcileErr != nil {
		return a.reconcileErr
	}
	return a.Simulator.Reconcile(ctx, c)
}

func TestServiceStartupAndExplicitRecovery(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	c := EmptyConfig()
	c.Softflowd = []SoftflowdConfig{flowConfig()}
	commitConfig(t, e, c)
	stopped := Clone(c)
	stopped.Softflowd[0].Enabled = false
	a := &runtimeTestAdapter{Simulator: NewSimulator(stopped), resumeErr: errors.New("injected unavailable binary")}
	e = testEngine(t, store, a)
	if len(a.resumed) != 1 || !Equal(a.resumed[0], c) {
		t.Fatalf("wrong startup configuration: %+v", a.resumed)
	}
	runtime, err := e.Runtime(context.Background())
	if err != nil || !strings.Contains(runtime.Error, "unavailable binary") {
		t.Fatalf("%+v %v", runtime, err)
	}
	if _, err := e.ReconcileServices(context.Background(), "admin", nil); err == nil {
		t.Fatal("runtime failure hidden")
	}
	a.resumeErr = nil
	runtime, err = e.ReconcileServices(context.Background(), "admin", nil)
	if err != nil || runtime.Error != "" || runtime.Softflowd[0].State != "simulated" {
		t.Fatalf("%+v %v", runtime, err)
	}
	if e.Snapshot().Revision != 1 || len(e.Snapshot().Transactions) != 1 {
		t.Fatal("runtime retry created a configuration revision")
	}
	view, err := e.View(context.Background())
	if err != nil || view.Drift {
		t.Fatalf("%+v %v", view, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	count := len(a.resumed)
	if _, err := e.ReconcileServices(ctx, "admin", nil); !errors.Is(err, context.Canceled) || len(a.resumed) != count {
		t.Fatalf("canceled retry mutated runtime: %v", err)
	}
}

func TestServicePendingRestartAndRecoveryFailureGating(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		store := testStore(t)
		e := testEngine(t, store, NewSimulator(EmptyConfig()))
		c := EmptyConfig()
		c.Softflowd = []SoftflowdConfig{flowConfig()}
		tx := submit(t, e, 0, c)
		a := &runtimeTestAdapter{Simulator: NewSimulator(c)}
		e = testEngine(t, store, a)
		if len(a.resumed) != 1 || !Equal(a.resumed[0], c) || e.Snapshot().Active != tx.ID {
			t.Fatal("pending runtime not resumed")
		}
		a.resumeErr = errors.New("candidate runtime failed")
		e = testEngine(t, store, a)
		if e.Snapshot().Active != "" || e.Snapshot().Transactions[tx.ID].Status != "rolled_back" {
			t.Fatal("failed pending service was not rolled back")
		}
	})
	t.Run("blocked", func(t *testing.T) {
		store := testStore(t)
		a := &runtimeTestAdapter{Simulator: NewSimulator(EmptyConfig())}
		e := testEngine(t, store, a)
		a.reconcileErr = errors.New("rollback unavailable")
		if _, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: 30}); err == nil {
			t.Fatal("injected apply succeeded")
		}
		a.resumed = nil
		e = testEngine(t, store, a)
		if len(a.resumed) != 0 {
			t.Fatal("services restarted despite failed recovery")
		}
		if _, err := e.ReconcileServices(context.Background(), "admin", nil); !errors.Is(err, ErrConflict) {
			t.Fatalf("failed recovery bypassed: %v", err)
		}
	})
}

func TestVLANServiceExampleAndLegacyNormalization(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "vlan-softflowd.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request Request
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	var legacy Config
	if err := json.Unmarshal([]byte(`{"interfaces":[],"routes":[],"policy_rules":[],"firewall":{"policy":"accept","rules":[]}}`), &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.Normalize()
	if !Equal(legacy, EmptyConfig()) || legacy.Softflowd == nil {
		t.Fatal("legacy configuration changed meaning")
	}
}
