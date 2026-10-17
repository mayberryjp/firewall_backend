package control

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"
)

var (
	ErrConflict         = errors.New("configuration conflict")
	ErrNotFound         = errors.New("transaction not found")
	ErrRevisionNotFound = errors.New("revision not found")
	ErrValidation       = errors.New("invalid request")
)

type Transaction struct {
	ID           string        `json:"id"`
	Actor        string        `json:"actor"`
	Status       string        `json:"status"`
	BaseRevision uint64        `json:"base_revision"`
	Candidate    Config        `json:"candidate"`
	Previous     Config        `json:"previous"`
	Deadline     time.Time     `json:"confirmation_deadline"`
	Error        string        `json:"error,omitempty"`
	Description  string        `json:"description,omitempty"`
	SubmittedAt  *time.Time    `json:"submitted_at"`
	CommittedAt  *time.Time    `json:"committed_at"`
	CommittedBy  string        `json:"committed_by,omitempty"`
	RestoredFrom *uint64       `json:"restored_from_revision,omitempty"`
	KernelBefore *KernelConfig `json:"kernel_before,omitempty"`
	KernelAfter  *KernelConfig `json:"kernel_after,omitempty"`
}

type State struct {
	Scope          string                  `json:"scope"`
	Revision       uint64                  `json:"revision"`
	Desired        Config                  `json:"desired"`
	Active         string                  `json:"active_transaction,omitempty"`
	Transactions   map[string]*Transaction `json:"transactions"`
	InitializedAt  *time.Time              `json:"initialized_at"`
	KernelBaseline KernelConfig            `json:"kernel_baseline"`
}

type Request struct {
	BaseRevision   uint64 `json:"base_revision"`
	ConfirmSeconds int    `json:"confirm_timeout_seconds"`
	Config         Config `json:"config"`
	Description    string `json:"description,omitempty"`
}

type View struct {
	Revision uint64       `json:"revision"`
	Desired  Config       `json:"desired"`
	Observed Config       `json:"observed"`
	Drift    bool         `json:"drift"`
	Active   *Transaction `json:"active_transaction,omitempty"`
}

type Engine struct {
	mu           sync.Mutex
	state        State
	store        Journal
	adapter      Adapter
	now          func() time.Time
	log          *slog.Logger
	runtimeError string
}

func NewEngine(store Journal, adapter Adapter, logger *slog.Logger) (*Engine, error) {
	state, err := store.Load()
	if err != nil {
		return nil, err
	}
	state.KernelBaseline.Normalize()
	if err := validateKernelJournal(state); err != nil {
		return nil, err
	}
	if state.Scope == "" {
		state.Scope = adapter.Scope()
		if state.Revision == 0 && len(state.Transactions) == 0 {
			now := time.Now().UTC()
			state.InitializedAt = &now
		}
		if err := store.Save(state); err != nil {
			return nil, fmt.Errorf("bind state to adapter scope: %w", err)
		}
	} else if state.Scope != adapter.Scope() {
		return nil, fmt.Errorf("state belongs to scope %q, not %q", state.Scope, adapter.Scope())
	}
	if owner, ok := adapter.(kernelOwnershipAdapter); ok {
		keys := state.Desired.Kernel
		if state.Active != "" {
			if active := state.Transactions[state.Active]; active != nil {
				keys = kernelUnion(keys, active.Candidate.Kernel)
				if active.KernelBefore != nil {
					keys = kernelUnion(keys, *active.KernelBefore)
				}
			}
		}
		if err := owner.checkKernelOwnership(keys); err != nil {
			return nil, err
		}
	}
	e := &Engine{store: store, adapter: adapter, state: state, now: time.Now, log: logger}
	if state.Active != "" {
		t, ok := state.Transactions[state.Active]
		if !ok {
			return nil, fmt.Errorf("invalid journal: active transaction missing")
		}
		switch t.Status {
		case "applying", "rolling_back", "recovery_failed":
			if err := e.rollback(t, "startup recovery"); err != nil {
				logger.Error("startup recovery failed; writes blocked", "error", err)
			}
		case "pending_confirmation":
			if !e.now().Before(t.Deadline) {
				if err := e.rollback(t, "confirmation expired during shutdown"); err != nil {
					logger.Error("startup rollback failed; writes blocked", "error", err)
				}
			}
		default:
			return nil, fmt.Errorf("invalid active transaction status %q", t.Status)
		}
	}
	if runtimeAdapter, ok := adapter.(RuntimeAdapter); ok {
		expected := e.state.Desired
		canResume := true
		if e.state.Active != "" {
			active := e.state.Transactions[e.state.Active]
			if active.Status == "pending_confirmation" {
				expected = active.Candidate
			} else {
				canResume = false
			}
		}
		if canResume {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := runtimeAdapter.Resume(ctx, expected)
			cancel()
			if err != nil {
				e.runtimeError = err.Error()
				logger.Error("service startup reconciliation failed; inspect runtime status", "error", err)
				if e.state.Active != "" {
					if rollbackErr := e.rollback(e.state.Transactions[e.state.Active], "service startup reconciliation failed: "+err.Error()); rollbackErr != nil {
						logger.Error("startup service rollback failed", "error", rollbackErr)
					}
				}
			}
		}
	}
	return e, nil
}

func (e *Engine) Snapshot() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Clone(e.state)
}

func (e *Engine) View(ctx context.Context) (View, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	expected := e.state.Desired
	var active *Transaction
	if e.state.Active != "" {
		active = e.state.Transactions[e.state.Active]
		if active.Status == "pending_confirmation" {
			expected = active.Candidate
		}
	}
	observed, err := e.adapter.Observe(ctx, expected)
	if err != nil {
		return View{}, err
	}
	drift := !Equal(expected, observed)
	if active != nil && active.Status == "pending_confirmation" {
		if err := e.verifyKernel(ctx, active.KernelAfter); err != nil {
			if !errors.Is(err, ErrConflict) {
				return View{}, err
			}
			drift = true
		}
	}
	return Clone(View{Revision: e.state.Revision, Desired: e.state.Desired, Observed: observed, Drift: drift, Active: active}), nil
}

func (e *Engine) Submit(ctx context.Context, actor string, r Request) (Transaction, error) {
	return e.submit(ctx, actor, r, nil)
}

func (e *Engine) submit(ctx context.Context, actor string, r Request, restoredFrom *uint64) (Transaction, error) {
	r.Config = Clone(r.Config)
	r.Config.Normalize()
	r.Description = strings.TrimSpace(r.Description)
	if len(r.Description) > 1024 {
		return Transaction{}, fmt.Errorf("%w: description must not exceed 1024 bytes", ErrValidation)
	}
	if err := r.Config.Validate(); err != nil {
		return Transaction{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if r.ConfirmSeconds < 10 || r.ConfirmSeconds > 300 {
		return Transaction{}, fmt.Errorf("%w: confirmation timeout must be 10..300 seconds", ErrValidation)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state.Active != "" || r.BaseRevision != e.state.Revision || e.state.Revision == math.MaxUint64 {
		return Transaction{}, ErrConflict
	}
	observed, err := e.adapter.Observe(ctx, e.state.Desired)
	if err != nil {
		return Transaction{}, fmt.Errorf("observe before commit: %w", err)
	}
	if !Equal(observed, e.state.Desired) {
		return Transaction{}, fmt.Errorf("%w: managed state has drifted", ErrConflict)
	}
	if err := e.adapter.Preflight(ctx, r.Config); err != nil {
		return Transaction{}, fmt.Errorf("preflight: %w", err)
	}
	if err := e.adapter.Preflight(ctx, e.state.Desired); err != nil {
		return Transaction{}, fmt.Errorf("rollback preflight: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Transaction{}, err
	}
	// Reject kind changes because they require destructive interface replacement.
	for _, before := range e.state.Desired.Interfaces {
		for _, after := range r.Config.Interfaces {
			if before.Name == after.Name && before.Kind != after.Kind {
				return Transaction{}, fmt.Errorf("%w: interface kind changes require separate confirmed transactions", ErrValidation)
			}
			if before.Name == after.Name && before.VLAN != nil && after.VLAN != nil && *before.VLAN != *after.VLAN {
				return Transaction{}, fmt.Errorf("%w: VLAN parent/ID changes require a new interface name or separate confirmed deletion and creation", ErrValidation)
			}
		}
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Transaction{}, err
	}
	kernelBefore, kernelAfter, err := e.captureKernel(ctx, r.Config)
	if err != nil {
		return Transaction{}, fmt.Errorf("capture kernel rollback values: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Transaction{}, err
	}
	submittedAt := e.now().UTC()
	priorBaseline := Clone(e.state.KernelBaseline)
	if kernelBefore != nil {
		e.state.KernelBaseline = kernelUnion(*kernelBefore, e.state.KernelBaseline)
	}
	t := &Transaction{ID: fmt.Sprintf("%x", id), Actor: actor, Status: "applying", BaseRevision: e.state.Revision,
		Candidate: r.Config, Previous: Clone(e.state.Desired), Deadline: submittedAt.Add(time.Duration(r.ConfirmSeconds) * time.Second),
		Description: r.Description, SubmittedAt: &submittedAt, RestoredFrom: restoredFrom, KernelBefore: kernelBefore, KernelAfter: kernelAfter}
	e.state.Transactions[t.ID], e.state.Active = t, t.ID
	if err := e.store.Save(e.state); err != nil {
		delete(e.state.Transactions, t.ID)
		e.state.Active = ""
		e.state.KernelBaseline = priorBaseline
		return Transaction{}, fmt.Errorf("persist intent: %w", err)
	}
	e.log.Info("transaction applying", "transaction", t.ID, "actor", actor, "base_revision", r.BaseRevision)
	// Once intent is durable, disconnecting a client must not interrupt recovery.
	opctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = e.writeKernel(opctx, t.KernelAfter)
	if err == nil {
		err = e.adapter.Reconcile(opctx, t.Candidate)
	}
	if err == nil {
		var actual Config
		actual, err = e.adapter.Observe(opctx, t.Candidate)
		if err == nil && !Equal(actual, t.Candidate) {
			err = fmt.Errorf("post-apply verification mismatch")
		}
	}
	if err == nil {
		err = e.verifyKernel(opctx, t.KernelAfter)
	}
	if err == nil && !e.now().Before(t.Deadline) {
		err = fmt.Errorf("confirmation deadline elapsed while applying")
	}
	if err != nil {
		rollbackErr := e.rollback(t, err.Error())
		return Clone(*t), errors.Join(fmt.Errorf("apply failed: %w", err), rollbackErr)
	}
	t.Status = "pending_confirmation"
	if err := e.store.Save(e.state); err != nil {
		rollbackErr := e.rollback(t, "could not persist pending confirmation")
		return Clone(*t), errors.Join(err, rollbackErr)
	}
	e.log.Info("transaction awaiting confirmation", "transaction", t.ID, "deadline", t.Deadline)
	return Clone(*t), nil
}

func (e *Engine) Confirm(ctx context.Context, id, actor string) (Transaction, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.state.Transactions[id]
	if !ok {
		return Transaction{}, ErrNotFound
	}
	if t.Status == "committed" {
		return Clone(*t), nil
	}
	if e.state.Active != id || t.Status != "pending_confirmation" {
		return Clone(*t), ErrConflict
	}
	if e.state.Revision == math.MaxUint64 {
		return Clone(*t), fmt.Errorf("%w: revision counter exhausted", ErrConflict)
	}
	if !e.now().Before(t.Deadline) {
		err := e.rollback(t, "confirmation expired")
		return Clone(*t), errors.Join(ErrConflict, err)
	}
	actual, err := e.adapter.Observe(ctx, t.Candidate)
	if err != nil {
		return Clone(*t), err
	}
	if !Equal(actual, t.Candidate) {
		return Clone(*t), fmt.Errorf("%w: candidate drifted before confirmation", ErrConflict)
	}
	if err := e.verifyKernel(ctx, t.KernelAfter); err != nil {
		return Clone(*t), err
	}
	if !e.now().Before(t.Deadline) {
		err := e.rollback(t, "confirmation expired during verification")
		return Clone(*t), errors.Join(ErrConflict, err)
	}
	if err := ctx.Err(); err != nil {
		return Clone(*t), err
	}
	before := Clone(e.state)
	committedAt := e.now().UTC()
	t.CommittedAt, t.CommittedBy = &committedAt, actor
	e.state.Revision++
	e.state.Desired, e.state.Active, t.Status = Clone(t.Candidate), "", "committed"
	if err := e.store.Save(e.state); err != nil {
		e.state = before
		return Transaction{}, fmt.Errorf("persist confirmation: %w", err)
	}
	e.log.Info("transaction committed", "transaction", id, "actor", actor, "revision", e.state.Revision, "restored_from_revision", t.RestoredFrom)
	return Clone(*t), nil
}

func (e *Engine) Rollback(id, actor string) (Transaction, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t, ok := e.state.Transactions[id]
	if !ok {
		return Transaction{}, ErrNotFound
	}
	if t.Status == "rolled_back" {
		return Clone(*t), nil
	}
	if e.state.Active != id {
		return Clone(*t), ErrConflict
	}
	err := e.rollback(t, "rollback requested by "+actor)
	return Clone(*t), err
}

func (e *Engine) rollback(t *Transaction, reason string) error {
	t.Status, t.Error = "rolling_back", reason
	if err := e.store.Save(e.state); err != nil {
		t.Status, t.Error = "recovery_failed", reason+"; persist rollback intent: "+err.Error()
		e.log.Error("rollback intent persistence failed; writes blocked", "transaction", t.ID, "error", t.Error)
		return fmt.Errorf("%s", t.Error)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := errors.Join(e.writeKernel(ctx, t.KernelBefore), e.adapter.Reconcile(ctx, t.Previous))
	if err == nil {
		var observed Config
		observed, err = e.adapter.Observe(ctx, t.Previous)
		if err == nil && !Equal(observed, t.Previous) {
			err = fmt.Errorf("rollback verification mismatch")
		}
	}
	if err == nil {
		err = e.verifyKernel(ctx, t.KernelBefore)
	}
	if err != nil {
		t.Status, t.Error = "recovery_failed", reason+"; rollback: "+err.Error()
		saveErr := e.store.Save(e.state)
		e.log.Error("rollback failed; writes blocked", "transaction", t.ID, "error", t.Error, "persistence_error", saveErr)
		return errors.Join(fmt.Errorf("%s", t.Error), saveErr)
	}
	t.Status, e.state.Active = "rolled_back", ""
	if err := e.store.Save(e.state); err != nil {
		t.Status, t.Error, e.state.Active = "recovery_failed", reason+"; persist rollback result: "+err.Error(), t.ID
		e.log.Error("rollback result persistence failed; writes blocked", "transaction", t.ID, "error", t.Error)
		return err
	}
	e.log.Warn("transaction rolled back", "transaction", t.ID, "reason", reason)
	return nil
}

func (e *Engine) Tick() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state.Active == "" {
		return nil
	}
	t := e.state.Transactions[e.state.Active]
	if t.Status == "pending_confirmation" && !e.now().Before(t.Deadline) {
		return e.rollback(t, "confirmation timeout")
	}
	return nil
}

func (e *Engine) Watch(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Tick(); err != nil {
				e.log.Error("transaction watchdog failed", "error", err)
			}
		}
	}
}
