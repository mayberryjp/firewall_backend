package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func kernelCandidate() Config {
	c := EmptyConfig()
	c.Kernel.Namespace["net.core.somaxconn"] = "8192"
	c.Kernel.Namespace["net.ipv4.tcp_rmem"] = "4096 131072 16777216"
	c.Kernel.Host["net.core.netdev_max_backlog"] = "2000"
	return c
}

func TestKernelAllowlistValidation(t *testing.T) {
	if err := kernelCandidate().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range KernelCatalog() {
		if p.Scope != "namespace" && p.Scope != "host" {
			t.Fatal(p)
		}
		if err := validateKernelValue(p, p.simulated); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
	}
	tests := []KernelConfig{
		{Namespace: map[string]string{"../../kernel/panic": "1"}},
		{Namespace: map[string]string{"kernel.panic": "1"}},
		{Namespace: map[string]string{"net.core.netdev_budget": "1000"}},
		{Host: map[string]string{"net.ipv4.tcp_sack": "1"}},
		{Namespace: map[string]string{"net.ipv4.ip_forward": "1"}},
		{Namespace: map[string]string{"net.ipv4.tcp_sack": "2"}},
		{Namespace: map[string]string{"net.core.somaxconn": "01"}},
		{Namespace: map[string]string{"net.core.somaxconn": "+1"}},
		{Namespace: map[string]string{"net.core.somaxconn": "1\n"}},
		{Namespace: map[string]string{"net.core.somaxconn": "-1"}},
		{Namespace: map[string]string{"net.core.somaxconn": "2147483648"}},
		{Namespace: map[string]string{"net.ipv4.tcp_rmem": "4096 1024 8192"}},
		{Namespace: map[string]string{"net.ipv4.tcp_rmem": "4096  8192 16384"}},
		{Namespace: map[string]string{"net.ipv4.tcp_rmem": "4096\t8192\t16384"}},
		{Namespace: map[string]string{"net.ipv4.tcp_rmem": "4096 8192"}},
		{Namespace: map[string]string{"net.ipv4.ip_local_port_range": "40000 40000"}},
		{Namespace: map[string]string{"net.ipv4.ip_local_port_range": "40000 65536"}},
		{Namespace: map[string]string{"net.ipv4.tcp_congestion_control": "cubic;id"}},
	}
	for _, c := range tests {
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid value accepted: %+v", c)
		}
	}
}

func TestKernelOriginalValuesRemovalHistoryAndRestore(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	a := NewSimulator(EmptyConfig())
	original := KernelConfig{Namespace: map[string]string{"net.core.somaxconn": "7777", "net.ipv4.tcp_rmem": "4096 131072 6291456"},
		Host: map[string]string{"net.core.netdev_max_backlog": "1234"}}
	if err := a.WriteKernel(ctx, original); err != nil {
		t.Fatal(err)
	}
	e := testEngine(t, store, a)
	c := kernelCandidate()
	tx := submit(t, e, 0, c)
	if tx.KernelBefore == nil || tx.KernelAfter == nil || !kernelEqual(*tx.KernelBefore, original) {
		t.Fatalf("missing actual pre-write capture: %+v", tx)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !kernelEqual(persisted.KernelBaseline, original) || !kernelEqual(*persisted.Transactions[tx.ID].KernelBefore, original) {
		t.Fatal("baseline not durable before confirmation")
	}
	if _, err := e.Confirm(ctx, tx.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	tx = submit(t, e, 1, EmptyConfig())
	view, err := e.KernelView(ctx)
	if err != nil || view.Drift || !view.Configured.Empty() || !kernelEqual(view.Effective, original) || !kernelEqual(view.Observed, original) {
		t.Fatalf("%+v %v", view, err)
	}
	changed := Clone(original)
	changed.Namespace["net.core.somaxconn"] = "7000"
	if err := a.WriteKernel(ctx, changed); err != nil {
		t.Fatal(err)
	}
	full, err := e.View(ctx)
	if err != nil || !full.Drift {
		t.Fatalf("pending default restoration drift hidden: %+v %v", full, err)
	}
	if _, err := e.Confirm(ctx, tx.ID, "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("default restoration mismatch committed: %v", err)
	}
	if _, err := e.Rollback(tx.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	full, err = e.View(ctx)
	if err != nil || full.Drift || !Equal(full.Observed, c) {
		t.Fatalf("%+v %v", full, err)
	}
	commitConfig(t, e, EmptyConfig())
	if err := a.WriteKernel(ctx, changed); err != nil {
		t.Fatal(err)
	}
	// Released parameters must not be reset on unrelated subsequent transactions.
	commitConfig(t, e, candidate())
	actual, err := a.ReadKernel(ctx, original)
	if err != nil || !kernelEqual(actual, changed) {
		t.Fatalf("released values overwritten: %+v %v", actual, err)
	}
	e = testEngine(t, store, a)
	historical, err := e.GetRevision(1)
	if err != nil || !Equal(historical.Config, c) {
		t.Fatalf("%+v %v", historical, err)
	}
	restored, err := e.Restore(ctx, "admin", 1, RestoreRequest{BaseRevision: 3, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(ctx, restored.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if !kernelEqual(e.Snapshot().KernelBaseline, original) {
		t.Fatal("original baseline was replaced by a later external value")
	}
}

type kernelFaultAdapter struct {
	*Simulator
	writes     int
	failWrites map[int]bool
	readErr    error
	onRead     func()
	reconciles int
}

func (a *kernelFaultAdapter) Reconcile(ctx context.Context, c Config) error {
	a.reconciles++
	return a.Simulator.Reconcile(ctx, c)
}

func (a *kernelFaultAdapter) WriteKernel(ctx context.Context, c KernelConfig) error {
	a.writes++
	if a.failWrites[a.writes] {
		partial := KernelConfig{Namespace: map[string]string{}, Host: map[string]string{}}
		for k, v := range c.Namespace {
			partial.Namespace[k] = v
			break
		}
		if err := a.Simulator.WriteKernel(ctx, partial); err != nil {
			return err
		}
		return errors.New("injected partial sysctl write")
	}
	return a.Simulator.WriteKernel(ctx, c)
}

func (a *kernelFaultAdapter) ReadKernel(ctx context.Context, c KernelConfig) (KernelConfig, error) {
	if a.onRead != nil {
		a.onRead()
	}
	if a.readErr != nil {
		return KernelConfig{}, a.readErr
	}
	return a.Simulator.ReadKernel(ctx, c)
}

func TestKernelPartialFailureAndRecovery(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "compensated", true: "retry"}[rollbackFails], func(t *testing.T) {
			store := testStore(t)
			a := &kernelFaultAdapter{Simulator: NewSimulator(EmptyConfig()), failWrites: map[int]bool{1: true, 2: rollbackFails}}
			e := testEngine(t, store, a)
			tx, err := e.Submit(context.Background(), "admin", Request{Config: kernelCandidate(), ConfirmSeconds: 30})
			if err == nil {
				t.Fatal("partial kernel failure reported success")
			}
			if a.reconciles != 1 {
				t.Fatal("network compensation was skipped after kernel rollback failure")
			}
			if rollbackFails {
				if tx.Status != "recovery_failed" {
					t.Fatalf("%+v", tx)
				}
				if _, err := e.Submit(context.Background(), "admin", Request{Config: EmptyConfig(), ConfirmSeconds: 30}); !errors.Is(err, ErrConflict) {
					t.Fatal(err)
				}
				e = testEngine(t, store, a)
			} else if tx.Status != "rolled_back" {
				t.Fatalf("%+v", tx)
			}
			if e.Snapshot().Active != "" {
				t.Fatal("recovery did not complete")
			}
			values, err := a.ReadKernel(context.Background(), kernelCandidate().Kernel)
			if err != nil || !kernelEqual(values, *tx.KernelBefore) {
				t.Fatalf("%+v %v", values, err)
			}
		})
	}
}

func TestKernelCaptureFailureAndPersistenceFailureDoNotWrite(t *testing.T) {
	store := testStore(t)
	a := &kernelFaultAdapter{Simulator: NewSimulator(EmptyConfig()), readErr: errors.New("unreadable sysctl")}
	journal := &failingJournal{Journal: store, failAt: 2}
	e := testEngine(t, journal, a)
	if _, err := e.Submit(context.Background(), "admin", Request{Config: kernelCandidate(), ConfirmSeconds: 30}); err == nil {
		t.Fatal("capture error hidden")
	}
	a.readErr = nil
	if _, err := e.Submit(context.Background(), "admin", Request{Config: kernelCandidate(), ConfirmSeconds: 30}); err == nil {
		t.Fatal("intent persistence failure hidden")
	}
	if a.writes != 0 || len(e.Snapshot().Transactions) != 0 || !e.Snapshot().KernelBaseline.Empty() {
		t.Fatal("failed intent mutated kernel or baseline")
	}
}

func TestKernelCaptureRaceAndDeadline(t *testing.T) {
	store := testStore(t)
	a := &kernelFaultAdapter{Simulator: NewSimulator(EmptyConfig())}
	e := testEngine(t, store, a)
	c := kernelCandidate()
	commitConfig(t, e, c)
	a.onRead = func() {
		a.onRead = nil
		changed := Clone(c.Kernel)
		changed.Namespace["net.core.somaxconn"] = "9999"
		if err := a.Simulator.WriteKernel(context.Background(), changed); err != nil {
			t.Fatal(err)
		}
	}
	next := Clone(c)
	next.Kernel.Namespace["net.core.somaxconn"] = "16384"
	if _, err := e.Submit(context.Background(), "admin", Request{BaseRevision: 1, Config: next, ConfirmSeconds: 30}); !errors.Is(err, ErrConflict) {
		t.Fatalf("capture race accepted: %v", err)
	}
	if len(e.Snapshot().Transactions) != 1 {
		t.Fatal("invalid snapshot journaled")
	}
	if err := a.Simulator.WriteKernel(context.Background(), c.Kernel); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e.now = func() time.Time { return now }
	a.onRead = func() { now = now.Add(time.Minute); a.onRead = nil }
	tx := submit(t, e, 1, next)
	if tx.SubmittedAt == nil || !tx.Deadline.Equal(now.Add(30*time.Second)) {
		t.Fatal("capture consumed confirmation window")
	}
	now = tx.Deadline
	if err := e.Tick(); err != nil {
		t.Fatal(err)
	}
}

func TestKernelSnapshotsSurviveRestartAndRejectCorruption(t *testing.T) {
	for _, status := range []string{"applying", "pending_confirmation", "rolling_back", "recovery_failed"} {
		t.Run(status, func(t *testing.T) {
			store := testStore(t)
			a := NewSimulator(EmptyConfig())
			e := testEngine(t, store, a)
			tx := submit(t, e, 0, kernelCandidate())
			state := e.Snapshot()
			state.Transactions[tx.ID].Status = status
			if status == "pending_confirmation" {
				state.Transactions[tx.ID].Deadline = time.Now().Add(-time.Second)
			}
			if err := store.Save(state); err != nil {
				t.Fatal(err)
			}
			restarted := testEngine(t, store, a)
			if restarted.Snapshot().Active != "" {
				t.Fatal("kernel recovery not completed")
			}
			actual, err := a.ReadKernel(context.Background(), kernelCandidate().Kernel)
			if err != nil || !kernelEqual(actual, *tx.KernelBefore) {
				t.Fatalf("%+v %v", actual, err)
			}
			for _, mutate := range []func(*State){
				func(s *State) { s.Transactions[tx.ID].KernelBefore = nil },
				func(s *State) { delete(s.KernelBaseline.Host, "net.core.netdev_max_backlog") },
				func(s *State) { s.Transactions[tx.ID].KernelAfter.Namespace["net.core.somaxconn"] = "9000" },
			} {
				corrupt := restarted.Snapshot()
				mutate(&corrupt)
				if err := store.Save(corrupt); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Load(); err == nil {
					t.Fatal("corrupt recovery snapshot accepted")
				}
			}
		})
	}
}

type kernelOwnershipTestAdapter struct{ *Simulator }

func (a *kernelOwnershipTestAdapter) checkKernelOwnership(c KernelConfig) error {
	if len(c.Host) > 0 {
		return errors.New("host opt-in is disabled")
	}
	return nil
}

func TestKernelHostOwnershipRequiresOptInUntilReleaseIsConfirmed(t *testing.T) {
	store := testStore(t)
	a := NewSimulator(EmptyConfig())
	e := testEngine(t, store, a)
	commitConfig(t, e, kernelCandidate())
	guard := &kernelOwnershipTestAdapter{Simulator: a}
	if _, err := NewEngine(store, guard, testLogger()); err == nil {
		t.Fatal("host ownership silently abandoned on startup")
	}
	withoutHost := kernelCandidate()
	withoutHost.Kernel.Host = map[string]string{}
	tx := submit(t, e, 1, withoutHost)
	if _, err := NewEngine(store, guard, testLogger()); err == nil {
		t.Fatal("pending host restoration did not require opt-in")
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewEngine(store, guard, testLogger())
	if err != nil || restarted.Snapshot().Revision != 2 {
		t.Fatalf("historical host ownership prevents startup after release: %v", err)
	}
}

func TestKernelExampleIsExplicitAndLegacyEmptyInherits(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "kernel-mixed-conservative.json"))
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
	if len(request.Config.Kernel.Host) != 0 || len(request.Config.Kernel.Namespace) < 8 {
		t.Fatal("unexpected baseline scope")
	}
	if strings.Contains(string(data), "tcp_tw_reuse") || strings.Contains(string(data), "tcp_fin_timeout") {
		t.Fatal("unsafe cargo-cult tuning in baseline")
	}
	var old Config
	if err := json.Unmarshal([]byte(`{"firewall":{"policy":"accept"}}`), &old); err != nil {
		t.Fatal(err)
	}
	old.Normalize()
	if !old.Kernel.Empty() || !Equal(old, EmptyConfig()) {
		t.Fatal("legacy configuration opted into tuning")
	}
}
