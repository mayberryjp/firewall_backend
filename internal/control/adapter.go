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
	mu         sync.Mutex
	state      Config
	kernelLive KernelConfig
}

func NewSimulator(initial Config) *Simulator {
	live := Clone(initial.Kernel)
	live.Normalize()
	return &Simulator{state: Clone(initial), kernelLive: live}
}
func (s *Simulator) Scope() string { return "simulator" }
func (s *Simulator) Close() error  { return nil }

func (s *Simulator) Observe(ctx context.Context, _ Config) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	actual := Clone(s.state)
	actual.Kernel = s.readKernel(actual.Kernel)
	return actual, ctx.Err()
}

func (s *Simulator) Preflight(ctx context.Context, _ Config) error { return ctx.Err() }

func (s *Simulator) Reconcile(ctx context.Context, c Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = Clone(c)
	s.kernelLive = kernelUnion(s.kernelLive, c.Kernel)
	return nil
}

func (s *Simulator) readKernel(keys KernelConfig) KernelConfig {
	result := KernelConfig{}
	result.Normalize()
	for _, p := range kernelParameters {
		requested, source, target := keys.Namespace, s.kernelLive.Namespace, result.Namespace
		if p.Scope == "host" {
			requested, source, target = keys.Host, s.kernelLive.Host, result.Host
		}
		if _, ok := requested[p.Name]; ok {
			value, found := source[p.Name]
			if !found {
				value = p.simulated
			}
			target[p.Name] = value
		}
	}
	return result
}

func (s *Simulator) ReadKernel(ctx context.Context, keys KernelConfig) (KernelConfig, error) {
	if err := keys.Validate(); err != nil {
		return KernelConfig{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readKernel(keys), ctx.Err()
}

func (s *Simulator) WriteKernel(ctx context.Context, values KernelConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := values.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kernelLive = kernelUnion(s.kernelLive, values)
	return nil
}

func (s *Simulator) Resume(ctx context.Context, config Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Softflowd = Clone(config.Softflowd)
	return nil
}

func (s *Simulator) Runtime(ctx context.Context, _ Config) (RuntimeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := RuntimeState{Parents: []ParentInterface{}, Softflowd: []SoftflowdStatus{}}
	for _, config := range s.state.Softflowd {
		status := SoftflowdStatus{Name: config.Name, State: "disabled"}
		if config.Enabled {
			status.State = "simulated"
		}
		state.Softflowd = append(state.Softflowd, status)
	}
	return state, ctx.Err()
}
