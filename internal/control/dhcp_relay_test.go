package control

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func relayConfig() Config {
	c := candidate()
	c.Interfaces[0].Role = "lan"
	c.Interfaces[0].DHCPRelay = DHCPRelayConfig{Enabled: true, Servers: []string{"198.51.100.20", "198.51.100.10"}}
	c.Normalize()
	return c
}

func TestDHCPRelayValidation(t *testing.T) {
	c := relayConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"no servers": func(c *Config) { c.Interfaces[0].DHCPRelay.Servers = nil },
		"duplicate": func(c *Config) {
			c.Interfaces[0].DHCPRelay.Servers = []string{"198.51.100.1", "198.51.100.1"}
		},
		"down":    func(c *Config) { c.Interfaces[0].Up = false },
		"no IPv4": func(c *Config) { c.Interfaces[0].Addresses = []string{"2001:db8::1/64"} },
		"wireguard": func(c *Config) {
			c.Interfaces[0].Kind = "wireguard"
			c.Interfaces[0].WireGuard = &WireGuard{KeyRef: "wg0", ListenPort: 51820}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			next := Clone(c)
			mutate(&next)
			if err := next.Validate(); err == nil {
				t.Fatal("invalid relay configuration accepted")
			}
		})
	}
	for _, server := range []string{"", "server.example", "198.51.100.1:67", "198.51.100.0/24",
		"2001:db8::1", "::ffff:198.51.100.1", "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1",
		"255.255.255.255", "198.051.100.1", " 198.51.100.1"} {
		for _, enabled := range []bool{true, false} {
			next := Clone(c)
			next.Interfaces[0].DHCPRelay = DHCPRelayConfig{Enabled: enabled, Servers: []string{server}}
			if err := next.Validate(); err == nil {
				t.Fatalf("invalid server %q accepted (enabled=%v)", server, enabled)
			}
		}
	}
	c.Interfaces[0].DHCPRelay.Enabled = false
	c.Interfaces[0].DHCPRelay.Servers = nil
	c.Interfaces[0].Up = false
	c.Interfaces[0].Addresses = nil
	c.Firewall.NAT.Masquerade = nil
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled relay should not require an up link, IPv4 address, or servers: %v", err)
	}
}

func TestDHCPRelayBindingsAndArguments(t *testing.T) {
	c := relayConfig()
	c.Interfaces[0].Addresses = []string{"192.0.2.2/24", "192.0.2.10/24", "2001:db8::1/64"}
	bindings, err := dhcpRelayBindings(c.Interfaces)
	if err != nil || len(bindings) != 1 || bindings[0].Address != "192.0.2.10" {
		t.Fatalf("deterministic relay address selection: %+v %v", bindings, err)
	}
	want := []string{"--keep-in-foreground", "--conf-file=/dev/null", "--port=0", "--no-hosts", "--no-resolv",
		"--log-facility=-", "--pid-file=relay.pid", "--interface=wan",
		"--dhcp-relay=192.0.2.10,198.51.100.10", "--dhcp-relay=192.0.2.10,198.51.100.20"}
	if actual := dhcpRelayArgs(bindings, "relay.pid"); !reflect.DeepEqual(actual, want) {
		t.Fatalf("relay-only arguments: %q", actual)
	}
	reordered := Clone(c)
	reordered.Interfaces[0].DHCPRelay.Servers[0], reordered.Interfaces[0].DHCPRelay.Servers[1] =
		reordered.Interfaces[0].DHCPRelay.Servers[1], reordered.Interfaces[0].DHCPRelay.Servers[0]
	if !Equal(c, reordered) {
		t.Fatal("server ordering must not change effective configuration")
	}
	duplicate := Clone(c.Interfaces[0])
	duplicate.Name = "lan2"
	c.Interfaces = append(c.Interfaces, duplicate)
	if err := c.Validate(); err == nil {
		t.Fatal("ambiguous shared relay address accepted")
	}
}

func TestDHCPRelayPersistenceRollbackAndRuntimeRecovery(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	c := relayConfig()
	tx := submit(t, e, 0, c)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	disabled := Clone(c)
	disabled.Interfaces[0].DHCPRelay.Enabled = false
	tx = submit(t, e, 1, disabled)
	runtime, err := e.Runtime(context.Background())
	if err != nil || len(runtime.DHCPRelay) != 1 || runtime.DHCPRelay[0].State != "disabled" {
		t.Fatalf("disabled status: %+v %v", runtime, err)
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	state, err := store.Load()
	if err != nil || !Equal(state.Desired, c) {
		t.Fatalf("relay not persisted: %+v %v", state, err)
	}
	a := &runtimeTestAdapter{Simulator: NewSimulator(disabled), resumeErr: errors.New("relay unavailable")}
	e = testEngine(t, store, a)
	runtime, err = e.Runtime(context.Background())
	if err != nil || runtime.Error == "" {
		t.Fatalf("startup failure was hidden: %+v %v", runtime, err)
	}
	count := len(a.resumed)
	denied := errors.New("relay permission denied")
	if _, err := e.ReconcileServices(context.Background(), "test", func(actual Config) error {
		if !Equal(actual, c) {
			t.Fatal("authorization did not see current runtime configuration")
		}
		return denied
	}); !errors.Is(err, denied) || len(a.resumed) != count {
		t.Fatal("unauthorized runtime reconciliation changed services")
	}
	a.resumeErr = nil
	runtime, err = e.ReconcileServices(context.Background(), "test", nil)
	if err != nil || runtime.Error != "" || len(runtime.DHCPRelay) != 1 || runtime.DHCPRelay[0].State != "simulated" {
		t.Fatalf("relay recovery: %+v %v", runtime, err)
	}
	view, err := e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("restart/recovery lost relay settings: %+v %v", view, err)
	}
	tx, err = e.Restore(context.Background(), "test", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if err != nil || len(tx.Candidate.Interfaces) != 0 {
		t.Fatalf("revision restore did not remove relay interface: %+v %v", tx, err)
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
}
