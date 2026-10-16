package control

import (
	"context"
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func validatePublicKey(s string) error {
	key, err := wgtypes.ParseKey(s)
	if err != nil || key == (wgtypes.Key{}) {
		return fmt.Errorf("invalid WireGuard public key")
	}
	return nil
}

// Observe reports only the owned scope; hints contain key references, never secrets.
// Reconcile must handle partial prior applications and be safe to retry.
type Adapter interface {
	Scope() string
	Close() error
	Observe(context.Context, Config) (Config, error)
	Preflight(context.Context, Config) error
	Reconcile(context.Context, Config) error
}

type Simulator struct {
	mu    sync.Mutex
	state Config
}

func NewSimulator(initial Config) *Simulator { return &Simulator{state: Clone(initial)} }
func (s *Simulator) Scope() string           { return "simulator" }
func (s *Simulator) Close() error            { return nil }

func (s *Simulator) Observe(ctx context.Context, _ Config) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Clone(s.state), ctx.Err()
}

func (s *Simulator) Preflight(ctx context.Context, _ Config) error { return ctx.Err() }

func (s *Simulator) Reconcile(ctx context.Context, c Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = Clone(c)
	return nil
}
