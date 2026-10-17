package control

import (
	"context"
	"fmt"
	"time"
)

func (e *Engine) runtimeConfig() Config {
	if e.state.Active != "" {
		t := e.state.Transactions[e.state.Active]
		if t.Status == "pending_confirmation" {
			return t.Candidate
		}
	}
	return e.state.Desired
}

func (e *Engine) Runtime(ctx context.Context) (RuntimeState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	adapter, ok := e.adapter.(RuntimeAdapter)
	if !ok {
		return RuntimeState{}, fmt.Errorf("adapter does not expose service runtime state")
	}
	state, err := adapter.Runtime(ctx, e.runtimeConfig())
	state.Error = e.runtimeError
	return Clone(state), err
}

func (e *Engine) ReconcileServices(ctx context.Context, actor string) (RuntimeState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state.Active != "" && e.state.Transactions[e.state.Active].Status != "pending_confirmation" {
		return RuntimeState{}, fmt.Errorf("%w: finish transaction recovery before reconciling services", ErrConflict)
	}
	if err := ctx.Err(); err != nil {
		return RuntimeState{}, err
	}
	adapter, ok := e.adapter.(RuntimeAdapter)
	if !ok {
		return RuntimeState{}, fmt.Errorf("adapter does not support service reconciliation")
	}
	opctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := adapter.Resume(opctx, e.runtimeConfig()); err != nil {
		e.runtimeError = err.Error()
		e.log.Error("service runtime reconciliation failed", "actor", actor, "error", err)
		return RuntimeState{}, err
	}
	e.runtimeError = ""
	e.log.Info("service runtime reconciled", "actor", actor)
	state, err := adapter.Runtime(opctx, e.runtimeConfig())
	return Clone(state), err
}
