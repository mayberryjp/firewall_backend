package control

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeGatewaySession struct {
	replies chan gatewayReply
	closed  chan struct{}
	once    sync.Once
}

func newFakeGatewaySession() *fakeGatewaySession {
	return &fakeGatewaySession{replies: make(chan gatewayReply, 32), closed: make(chan struct{})}
}
func (s *fakeGatewaySession) Send(ctx context.Context, seq uint64) (time.Time, error) {
	now := time.Now()
	select {
	case s.replies <- gatewayReply{sequence: seq, received: now.Add(time.Millisecond)}:
		return now, nil
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	}
}
func (s *fakeGatewaySession) Replies() <-chan gatewayReply { return s.replies }
func (s *fakeGatewaySession) Close() error                 { s.once.Do(func() { close(s.closed) }); return nil }

type blockingGatewayAdapter struct {
	*Simulator
	entered chan struct{}
	release chan struct{}
}

func (a *blockingGatewayAdapter) GatewayStatistics(ctx context.Context, c Config) ([]GatewayMonitorStatistics, error) {
	close(a.entered)
	select {
	case <-a.release:
		return a.Simulator.GatewayStatistics(ctx, c)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestGatewayStatisticsDoNotHoldEngineLock(t *testing.T) {
	a := &blockingGatewayAdapter{Simulator: NewSimulator(EmptyConfig()), entered: make(chan struct{}), release: make(chan struct{})}
	e := testEngine(t, testStore(t), a)
	done := make(chan error, 1)
	defer func() {
		close(a.release)
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("statistics request did not finish")
		}
	}()
	go func() {
		_, err := e.Statistics(context.Background(), StatisticsQuery{Section: StatisticsGateways})
		done <- err
	}()
	<-a.entered
	snapshot := make(chan struct{})
	go func() { e.Snapshot(); close(snapshot) }()
	select {
	case <-snapshot:
	case <-time.After(time.Second):
		t.Fatal("gateway statistics held the engine lock during collection")
	}
}

func TestGatewayManagerLifecycleAndFailure(t *testing.T) {
	var sessions []*fakeGatewaySession
	fail := false
	m := newGatewayManager(func(context.Context, GatewayMonitor) (gatewaySession, error) {
		if fail {
			return nil, errors.New("probe factory failed")
		}
		s := newFakeGatewaySession()
		sessions = append(sessions, s)
		return s, nil
	}, testLogger())
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	c := gatewayConfig()
	if err := m.Reconcile(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(context.Background(), c); err != nil || len(sessions) != 1 {
		t.Fatalf("unchanged monitor was restarted: %d %v", len(sessions), err)
	}
	w := m.workers["wan1"]
	for i := 0; i < 10; i++ {
		var wg sync.WaitGroup
		for n := 0; n < 4; n++ {
			wg.Add(1)
			go func() { defer wg.Done(); m.Statistics(c.GatewayMonitors) }()
		}
		wg.Wait()
	}
	sessions[0].replies <- gatewayReply{err: errors.New("socket failed")}
	select {
	case <-w.done:
	case <-time.After(time.Second):
		t.Fatal("failed worker did not exit")
	}
	if s := m.Statistics(c.GatewayMonitors)[0]; s.ProcessState != "exited" || s.Health != "unknown" || s.Error == "" {
		t.Fatalf("socket error was hidden: %+v", s)
	}
	if err := m.Reconcile(context.Background(), c); err != nil || len(sessions) != 2 {
		t.Fatalf("repair failed: %v", err)
	}
	w = m.workers["wan1"]
	w.cancel()
	<-w.done
	w.mu.Lock()
	w.cached.CollectedAt = gatewayTime(time.Now().Add(-time.Hour))
	w.refreshed = time.Now().Add(-time.Hour)
	w.mu.Unlock()
	if s := w.snapshot(time.Now()); s.SampleStatus != "stale" || s.Health != "unknown" {
		t.Fatalf("stale cache looked healthy: %+v", s)
	}
	next := Clone(c)
	next.Routes[0].Metric++
	if err := m.StopChanged(next); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sessions[1].closed:
	default:
		t.Fatal("network mutation did not close probes first")
	}
	fail = true
	if err := m.Reconcile(context.Background(), next); err == nil {
		t.Fatal("start failure was swallowed")
	}
	fail = false
	if err := m.Reconcile(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	disabled := Clone(c)
	disabled.GatewayMonitors[0].Enabled = false
	if err := m.Reconcile(context.Background(), disabled); err != nil {
		t.Fatal(err)
	}
	if s := m.Statistics(disabled.GatewayMonitors)[0]; s.ProcessState != "disabled" || s.RTTAvgMS != nil {
		t.Fatalf("disabled monitor retained live metrics: %+v", s)
	}
}
