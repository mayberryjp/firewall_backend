package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type gatewayReply struct {
	sequence uint64
	received time.Time
	err      error
}

type gatewaySession interface {
	Send(context.Context, uint64) (time.Time, error)
	Replies() <-chan gatewayReply
	Close() error
}

type gatewayWorker struct {
	config    GatewayMonitor
	session   gatewaySession
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	cached    GatewayMonitorStatistics
	refreshed time.Time
	closeErr  error
}

func startGatewayWorker(config GatewayMonitor, session gatewaySession, log *slog.Logger) *gatewayWorker {
	ctx, cancel := context.WithCancel(context.Background())
	window := newGatewayWindow(config, time.Now())
	w := &gatewayWorker{config: config, session: session, cancel: cancel, done: make(chan struct{}),
		cached: window.sample(time.Now()), refreshed: time.Now()}
	go w.run(ctx, window, log)
	return w
}

func (w *gatewayWorker) run(ctx context.Context, window *gatewayWindow, log *slog.Logger) {
	defer close(w.done)
	defer func() {
		err := w.session.Close()
		w.mu.Lock()
		w.closeErr = err
		w.mu.Unlock()
		if err != nil {
			log.Error("gateway monitor socket close failed", "monitor", w.config.Name, "error", err)
		}
	}()
	failed := func(err error) {
		w.mu.Lock()
		w.cached.ProcessState, w.cached.SampleStatus, w.cached.Health = "exited", "unavailable", "unknown"
		w.cached.HealthChangedAt = nil
		w.cached.Error = err.Error()
		w.mu.Unlock()
		log.Error("gateway monitor failed", "monitor", w.config.Name, "error", err)
	}
	refresh := func() error {
		// Apply already-received replies before considering their deadlines lost.
		for i := 0; i < 32; i++ {
			select {
			case reply := <-w.session.Replies():
				if reply.err != nil {
					return reply.err
				}
				window.reply(reply.sequence, reply.received)
			default:
				i = 32
			}
		}
		now := time.Now()
		sample := window.sample(now)
		w.mu.Lock()
		w.cached, w.refreshed = sample, now
		w.mu.Unlock()
		return nil
	}
	var sequence uint64
	send := func() error {
		sequence++
		sent, err := w.session.Send(ctx, sequence)
		if err != nil {
			return err
		}
		window.sent(sequence, sent)
		return refresh()
	}
	if err := send(); err != nil {
		if ctx.Err() == nil {
			failed(err)
		}
		return
	}
	probes := time.NewTicker(time.Duration(w.config.ProbeIntervalMS) * time.Millisecond)
	heartbeat := time.NewTicker(250 * time.Millisecond)
	defer probes.Stop()
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case reply := <-w.session.Replies():
			if reply.err != nil {
				failed(reply.err)
				return
			}
			window.reply(reply.sequence, reply.received)
			if err := refresh(); err != nil {
				failed(err)
				return
			}
		case <-probes.C:
			if err := send(); err != nil {
				if ctx.Err() == nil {
					failed(err)
				}
				return
			}
		case <-heartbeat.C:
			if err := refresh(); err != nil {
				failed(err)
				return
			}
		}
	}
}

func (w *gatewayWorker) snapshot(now time.Time) GatewayMonitorStatistics {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := Clone(w.cached)
	staleAfter := time.Duration(max(1000, 3*w.config.ProbeIntervalMS)) * time.Millisecond
	if result.ProcessState == "running" && now.Sub(w.refreshed) > staleAfter {
		result.SampleStatus, result.Health, result.Error = "stale", "unknown", "gateway sampling stalled"
		result.HealthChangedAt = nil
	}
	return result
}

type gatewayManager struct {
	mu      sync.Mutex
	workers map[string]*gatewayWorker
	network Config
	open    func(context.Context, GatewayMonitor) (gatewaySession, error)
	log     *slog.Logger
}

func newGatewayManager(open func(context.Context, GatewayMonitor) (gatewaySession, error), log *slog.Logger) *gatewayManager {
	if log == nil {
		log = slog.Default()
	}
	return &gatewayManager{workers: map[string]*gatewayWorker{}, open: open, log: log}
}

func gatewayNetwork(c Config) Config {
	result := Clone(Config{Interfaces: c.Interfaces, Routes: c.Routes, Rules: c.Rules, Firewall: c.Firewall, Kernel: c.Kernel})
	result.Normalize()
	return result
}

func (m *gatewayManager) stopLocked(predicate func(string, *gatewayWorker) bool) error {
	stopped := map[string]*gatewayWorker{}
	for name, w := range m.workers {
		if predicate(name, w) {
			w.cancel()
			stopped[name] = w
		}
	}
	var err error
	for name, w := range stopped {
		<-w.done
		err = errors.Join(err, w.closeErr)
		delete(m.workers, name)
	}
	return err
}

func (m *gatewayManager) StopChanged(c Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	networkChanged := !Equal(m.network, gatewayNetwork(c))
	wanted := map[string]GatewayMonitor{}
	for _, config := range c.GatewayMonitors {
		if config.Enabled {
			wanted[config.Name] = config
		}
	}
	return m.stopLocked(func(name string, w *gatewayWorker) bool {
		config, exists := wanted[name]
		return networkChanged || !exists || config != w.config
	})
}

func (m *gatewayManager) Reconcile(ctx context.Context, c Config) error {
	if err := m.StopChanged(c); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Record the applied network even if a later session fails to start.
	m.network = Clone(gatewayNetwork(c))
	for _, config := range c.GatewayMonitors {
		if !config.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if w, exists := m.workers[config.Name]; exists {
			select {
			case <-w.done:
				if err := m.stopLocked(func(name string, _ *gatewayWorker) bool { return name == config.Name }); err != nil {
					return err
				}
			default:
				continue
			}
		}
		session, err := m.open(ctx, config)
		if err != nil {
			return fmt.Errorf("start gateway monitor %s: %w", config.Name, err)
		}
		m.workers[config.Name] = startGatewayWorker(config, session, m.log)
	}
	return ctx.Err()
}

func (m *gatewayManager) Statistics(monitors []GatewayMonitor) []GatewayMonitorStatistics {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := inactiveGatewayStatistics(monitors, "not_running")
	for i, config := range monitors {
		if !config.Enabled {
			continue
		}
		if w, exists := m.workers[config.Name]; exists && w.config == config {
			result[i] = w.snapshot(time.Now())
		} else {
			result[i].SampleStatus, result[i].Error = "unavailable", "gateway monitor is not running with the expected settings"
		}
	}
	return result
}

func (m *gatewayManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked(func(string, *gatewayWorker) bool { return true })
}
