package control

import (
	"context"
	"strings"
	"testing"
)

func TestInterfaceRoleValidation(t *testing.T) {
	for _, role := range []string{"wan", "lan", "", "WAN", "LAN", "dmz", " lan", "lan "} {
		t.Run(role, func(t *testing.T) {
			c := candidate()
			c.Interfaces[0].Role = role
			c.Normalize()
			err := c.Validate()
			valid := role == "wan" || role == "lan"
			if (err == nil) != valid {
				t.Fatalf("role %q validation: %v", role, err)
			}
			if c.Interfaces[0].Role != role {
				t.Fatal("normalization must not infer or rewrite roles")
			}
		})
	}
	for _, c := range []Config{candidate(), vlanConfig()} {
		for _, role := range []string{"wan", "lan"} {
			for i := range c.Interfaces {
				c.Interfaces[i].Role = role
			}
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := candidate()
	c.Interfaces[0].Kind = "wireguard"
	c.Interfaces[0].WireGuard = &WireGuard{KeyRef: "wg0", ListenPort: 51820}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestInterfaceRolePersistenceRollbackAndRestore(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	wan := candidate()
	tx := submit(t, e, 0, wan)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	lan := Clone(wan)
	lan.Interfaces[0].Role = "lan"
	if Equal(wan, lan) {
		t.Fatal("configuration equality ignored the role change")
	}
	tx = submit(t, e, 1, lan)
	view, err := e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, lan) || !Equal(view.Desired, wan) {
		t.Fatalf("provisional role readback: %+v %v", view, err)
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, wan) {
		t.Fatalf("role rollback: %+v %v", view, err)
	}
	tx = submit(t, e, 1, lan)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	state, err := store.Load()
	if err != nil || !Equal(state.Desired, lan) {
		t.Fatalf("role not durably preserved: %+v %v", state, err)
	}
	e = testEngine(t, store, NewSimulator(state.Desired))
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, lan) {
		t.Fatalf("role lost after restart: %+v %v", view, err)
	}
	tx, err = e.Restore(context.Background(), "test", 1, RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if err != nil || !Equal(tx.Candidate, wan) {
		t.Fatalf("revision restore lost role: %+v %v", tx, err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestSavedConfigurationRequiresInterfaceRoles(t *testing.T) {
	store := testStore(t)
	untagged := candidate()
	untagged.Interfaces[0].Role = ""
	if err := store.Save(State{Desired: untagged, Transactions: map[string]*Transaction{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "role must be wan or lan") {
		t.Fatalf("untagged saved configuration not rejected explicitly: %v", err)
	}
}
