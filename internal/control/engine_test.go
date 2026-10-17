package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func testEngine(t *testing.T, store Journal, adapter Adapter) *Engine {
	t.Helper()
	e, err := NewEngine(store, adapter, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func candidate() Config {
	c := EmptyConfig()
	c.Interfaces = []Interface{{Name: "wan", Kind: "dummy", Role: "wan", MTU: 1500, Up: true, Addresses: []string{"192.0.2.10/24"}}}
	c.Routes = []Route{{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "wan", Table: 10000, Metric: 100}}
	c.Rules = []Rule{{Priority: 10000, Source: "192.0.2.0/24", Table: 10000}}
	c.Firewall = Firewall{Policy: "drop", Rules: []FirewallRule{{Source: "192.0.2.0/24", Action: "accept"}},
		NAT: NAT{Masquerade: []MasqueradeRule{{Family: "ipv4", Source: "192.0.2.0/24", OutInterface: "wan"}}}}
	c.Normalize()
	return c
}

func submit(t *testing.T, e *Engine, revision uint64, c Config) Transaction {
	t.Helper()
	tx, err := e.Submit(context.Background(), "test-admin", Request{BaseRevision: revision, ConfirmSeconds: 30, Config: c})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestCommitSeparatesDesiredFromObserved(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	tx := submit(t, e, 0, candidate())
	if tx.Status != "pending_confirmation" {
		t.Fatalf("status %s", tx.Status)
	}
	v, err := e.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(v.Desired, EmptyConfig()) || !Equal(v.Observed, candidate()) || v.Drift || v.Revision != 0 {
		t.Fatalf("incorrect provisional view: %+v", v)
	}
	result, err := e.Confirm(context.Background(), tx.ID, "confirmer")
	if err != nil || result.Status != "committed" {
		t.Fatalf("%+v %v", result, err)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Revision != 1 || persisted.Active != "" || !Equal(persisted.Desired, candidate()) {
		t.Fatalf("incorrect persisted commit: %+v", persisted)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "retry"); err != nil {
		t.Fatal("confirm must be idempotent", err)
	}
	if _, err := e.Submit(context.Background(), "test", Request{Config: candidate(), ConfirmSeconds: 30}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
}

func TestTimeoutAndLateConfirmation(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		t.Run(map[bool]string{false: "watchdog", true: "late-confirm"}[confirm], func(t *testing.T) {
			e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
			now := time.Now()
			e.now = func() time.Time { return now }
			tx := submit(t, e, 0, candidate())
			now = tx.Deadline
			if confirm {
				if _, err := e.Confirm(context.Background(), tx.ID, "test"); !errors.Is(err, ErrConflict) {
					t.Fatalf("late confirm: %v", err)
				}
			} else if err := e.Tick(); err != nil {
				t.Fatal(err)
			}
			v, err := e.View(context.Background())
			if err != nil || !Equal(v.Observed, EmptyConfig()) || v.Active != nil || v.Revision != 0 {
				t.Fatalf("%+v %v", v, err)
			}
			if e.Snapshot().Transactions[tx.ID].Status != "rolled_back" {
				t.Fatal("timeout did not roll back")
			}
		})
	}
}

type faultAdapter struct {
	*Simulator
	applyCalls  int
	failCalls   map[int]bool
	observeHook func()
}

func (a *faultAdapter) Reconcile(ctx context.Context, target Config) error {
	a.applyCalls++
	if a.failCalls[a.applyCalls] {
		partial := EmptyConfig()
		partial.Interfaces = Clone(target.Interfaces)
		if err := a.Simulator.Reconcile(ctx, partial); err != nil {
			return err
		}
		return errors.New("injected partial kernel failure")
	}
	return a.Simulator.Reconcile(ctx, target)
}

func (a *faultAdapter) Observe(ctx context.Context, hint Config) (Config, error) {
	if a.observeHook != nil {
		a.observeHook()
	}
	return a.Simulator.Observe(ctx, hint)
}

func TestPartialFailureAndRollbackFailure(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovered", true: "blocked-until-retry"}[rollbackFails], func(t *testing.T) {
			store := testStore(t)
			a := &faultAdapter{Simulator: NewSimulator(EmptyConfig()), failCalls: map[int]bool{1: true, 2: rollbackFails}}
			e := testEngine(t, store, a)
			tx, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: 30})
			if err == nil || tx.ID == "" {
				t.Fatalf("must return failure and transaction: %+v %v", tx, err)
			}
			expected := "rolled_back"
			if rollbackFails {
				expected = "recovery_failed"
			}
			if tx.Status != expected {
				t.Fatalf("got %s", tx.Status)
			}
			durable, err := store.Load()
			if err != nil || durable.Transactions[tx.ID].Status != expected {
				t.Fatalf("journal status: %+v %v", durable, err)
			}
			if rollbackFails {
				if _, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: 30}); !errors.Is(err, ErrConflict) {
					t.Fatalf("recovery failure must block writes: %v", err)
				}
				tx, err = e.Rollback(tx.ID, "operator")
				if err != nil || tx.Status != "rolled_back" {
					t.Fatalf("retry failed: %+v %v", tx, err)
				}
			}
		})
	}
}

func TestDriftBlocksCommitAndConfirmation(t *testing.T) {
	a := NewSimulator(EmptyConfig())
	e := testEngine(t, testStore(t), a)
	if err := a.Reconcile(context.Background(), candidate()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: 30}); !errors.Is(err, ErrConflict) {
		t.Fatalf("external drift accepted: %v", err)
	}
	if err := a.Reconcile(context.Background(), EmptyConfig()); err != nil {
		t.Fatal(err)
	}
	tx := submit(t, e, 0, candidate())
	if err := a.Reconcile(context.Background(), EmptyConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("candidate drift accepted: %v", err)
	}
	v, err := e.View(context.Background())
	if err != nil || !v.Drift {
		t.Fatalf("drift not reported: %+v %v", v, err)
	}
}

func TestRestartRecovery(t *testing.T) {
	for _, status := range []string{"applying", "rolling_back", "pending_confirmation", "recovery_failed"} {
		t.Run(status, func(t *testing.T) {
			store := testStore(t)
			a := NewSimulator(EmptyConfig())
			e := testEngine(t, store, a)
			tx := submit(t, e, 0, candidate())
			state := e.Snapshot()
			state.Transactions[tx.ID].Status = status
			if status == "pending_confirmation" {
				state.Transactions[tx.ID].Deadline = time.Now().Add(-time.Second)
			}
			if err := store.Save(state); err != nil {
				t.Fatal(err)
			}
			recovered := testEngine(t, store, a)
			v, err := recovered.View(context.Background())
			if err != nil || !Equal(v.Observed, EmptyConfig()) || v.Active != nil {
				t.Fatalf("restart did not recover: %+v %v", v, err)
			}
		})
	}
}

func TestRestartPreservesUnexpiredConfirmation(t *testing.T) {
	store := testStore(t)
	a := NewSimulator(EmptyConfig())
	e := testEngine(t, store, a)
	tx := submit(t, e, 0, candidate())
	e = testEngine(t, store, a)
	if e.Snapshot().Active != tx.ID {
		t.Fatal("unexpired candidate lost")
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSubmissionsHaveOneWinner(t *testing.T) {
	e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: 30})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly one winner, got %d", winners)
	}
}

type failingJournal struct {
	Journal
	calls  int
	failAt int
}

func (j *failingJournal) Save(s State) error {
	j.calls++
	if j.calls == j.failAt {
		return errors.New("injected disk failure")
	}
	return j.Journal.Save(s)
}

func TestJournalFailuresDoNotProduceSuccess(t *testing.T) {
	for _, failAt := range []int{2, 3, 4} {
		t.Run(map[int]string{2: "intent", 3: "pending-result", 4: "confirmation"}[failAt], func(t *testing.T) {
			base := testStore(t)
			j := &failingJournal{Journal: base, failAt: failAt}
			a := NewSimulator(EmptyConfig())
			e := testEngine(t, j, a)
			tx, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: 30})
			if failAt == 4 {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := e.Confirm(context.Background(), tx.ID, "admin"); err == nil {
					t.Fatal("confirmation persistence failure hidden")
				}
				if e.Snapshot().Revision != 0 || e.Snapshot().Active != tx.ID {
					t.Fatal("unpersisted confirmation published")
				}
				if _, err := e.Rollback(tx.ID, "cleanup"); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("persistence failure hidden")
			}
			observed, err := a.Observe(context.Background(), EmptyConfig())
			if err != nil || !Equal(observed, EmptyConfig()) {
				t.Fatalf("state not restored: %+v %v", observed, err)
			}
		})
	}
}

func TestConfirmationDeadlineRecheckedAfterObservation(t *testing.T) {
	a := &faultAdapter{Simulator: NewSimulator(EmptyConfig())}
	e := testEngine(t, testStore(t), a)
	now := time.Now()
	e.now = func() time.Time { return now }
	tx := submit(t, e, 0, candidate())
	a.observeHook = func() { now = tx.Deadline }
	if _, err := e.Confirm(context.Background(), tx.ID, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted expired confirmation: %v", err)
	}
	if e.Snapshot().Transactions[tx.ID].Status != "rolled_back" {
		t.Fatal("expired confirmation did not restore previous state")
	}
}

func TestStoreLockAndScopeBinding(t *testing.T) {
	store := testStore(t)
	if other, err := OpenStore(store.path); err == nil {
		other.Close()
		t.Fatal("second writer acquired journal")
	}
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	state := e.Snapshot()
	state.Scope = "different-namespace"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(store, NewSimulator(EmptyConfig()), testLogger()); err == nil {
		t.Fatal("scope mismatch accepted")
	}
}

func TestRollbackIntentFailureBlocksFurtherWrites(t *testing.T) {
	j := &failingJournal{Journal: testStore(t), failAt: 4}
	e := testEngine(t, j, NewSimulator(EmptyConfig()))
	tx := submit(t, e, 0, candidate())
	result, err := e.Rollback(tx.ID, "operator")
	if err == nil || result.Status != "recovery_failed" {
		t.Fatalf("rollback persistence failure hidden: %+v %v", result, err)
	}
	if _, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: 30}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unsafe write after persistence failure: %v", err)
	}
	if _, err := e.Rollback(tx.ID, "retry"); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledSubmissionDoesNotCreateIntent(t *testing.T) {
	e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Submit(ctx, "admin", Request{Config: candidate(), ConfirmSeconds: 30}); err == nil {
		t.Fatal("canceled request accepted")
	}
	if len(e.Snapshot().Transactions) != 0 {
		t.Fatal("canceled request journaled")
	}
}

func TestInvalidTimeoutAndKindChangeLeaveStateUntouched(t *testing.T) {
	e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
	for _, timeout := range []int{0, 9, 301} {
		if _, err := e.Submit(context.Background(), "admin", Request{Config: candidate(), ConfirmSeconds: timeout}); !errors.Is(err, ErrValidation) {
			t.Fatalf("timeout %d accepted: %v", timeout, err)
		}
	}
	tx := submit(t, e, 0, candidate())
	if _, err := e.Confirm(context.Background(), tx.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	c := candidate()
	c.Interfaces[0].Kind = "wireguard"
	c.Interfaces[0].WireGuard = &WireGuard{KeyRef: "wg", ListenPort: 51820}
	if _, err := e.Submit(context.Background(), "admin", Request{BaseRevision: 1, Config: c, ConfirmSeconds: 30}); !errors.Is(err, ErrValidation) {
		t.Fatalf("destructive kind replacement accepted: %v", err)
	}
}
