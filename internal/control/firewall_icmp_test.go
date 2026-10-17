package control

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestICMPSettingPersistenceRollbackAndRestore(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	disabled := EmptyConfig()
	value := false
	disabled.Firewall.AllowAllICMP = &value
	tx := submit(t, e, 0, disabled)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	e = testEngine(t, store, NewSimulator(disabled))
	view, err := e.View(context.Background())
	if err != nil || view.Drift || view.Desired.Firewall.allowsAllICMP() || view.Observed.Firewall.allowsAllICMP() {
		t.Fatalf("disabled setting not persisted: %+v %v", view, err)
	}
	tx = submit(t, e, 1, EmptyConfig())
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Desired.Firewall.allowsAllICMP() {
		t.Fatal("rollback did not restore disabled setting")
	}
	tx, err = e.Restore(context.Background(), "test", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Candidate.Firewall.allowsAllICMP() {
		t.Fatal("initial revision lost enabled setting")
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyICMPDefaultMigration(t *testing.T) {
	store := testStore(t)
	data := `{"scope":"simulator","revision":0,"desired":{"firewall":{"policy":"accept","rules":[]}},"transactions":{}}`
	if err := os.WriteFile(store.path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := store.Load()
	if err != nil || !state.ICMPDefaultMigration || !state.Desired.Firewall.allowsAllICMP() {
		t.Fatalf("legacy setting not marked for migration: %+v %v", state, err)
	}
	e := testEngine(t, store, NewSimulator(state.Desired))
	view, err := e.View(context.Background())
	if err != nil || view.Drift || !view.Desired.Firewall.allowsAllICMP() {
		t.Fatalf("legacy default migration: %+v %v", view, err)
	}
	state, err = store.Load()
	if err != nil || state.ICMPDefaultMigration || state.Desired.Firewall.AllowAllICMP == nil || !*state.Desired.Firewall.AllowAllICMP {
		t.Fatalf("migration not durably completed: %+v %v", state, err)
	}
}

func TestICMPMigrationPreservesPendingExplicitDisable(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	disabled := EmptyConfig()
	value := false
	disabled.Firewall.AllowAllICMP = &value
	tx := submit(t, e, 0, disabled)
	state := e.Snapshot()
	state.Desired.Firewall.AllowAllICMP = nil
	state.Transactions[tx.ID].Previous.Firewall.AllowAllICMP = nil
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	e = testEngine(t, store, NewSimulator(disabled))
	view, err := e.View(context.Background())
	if err != nil || view.Drift || view.Active == nil || view.Active.ID != tx.ID || view.Observed.Firewall.allowsAllICMP() {
		t.Fatalf("migration changed pending explicit disable: %+v %v", view, err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Desired.Firewall.allowsAllICMP() {
		t.Fatal("confirmation lost explicit disable")
	}
}

type failingICMPMigrator struct {
	*Simulator
}

func (*failingICMPMigrator) migrateICMPDefault(context.Context, Firewall) error {
	return errors.New("ICMP migration failed")
}

func TestICMPMigrationFailureRemainsPending(t *testing.T) {
	store := testStore(t)
	_, err := NewEngine(store, &failingICMPMigrator{NewSimulator(EmptyConfig())}, testLogger())
	if err == nil {
		t.Fatal("migration error was hidden")
	}
	state, err := store.Load()
	if err != nil || !state.ICMPDefaultMigration {
		t.Fatalf("failed migration not retryable: %+v %v", state, err)
	}
	testEngine(t, store, NewSimulator(EmptyConfig()))
	state, err = store.Load()
	if err != nil || state.ICMPDefaultMigration {
		t.Fatalf("migration retry not persisted: %+v %v", state, err)
	}
}
