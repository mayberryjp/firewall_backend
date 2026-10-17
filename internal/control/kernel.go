package control

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type KernelConfig struct {
	Namespace map[string]string `json:"namespace"`
	Host      map[string]string `json:"host"`
}

type KernelParameter struct {
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	Kind        string `json:"kind"`
	Min         int64  `json:"min"`
	Max         int64  `json:"max"`
	Count       int    `json:"count,omitempty"`
	Description string `json:"description"`
	simulated   string
}

type KernelAdapter interface {
	ReadKernel(context.Context, KernelConfig) (KernelConfig, error)
	WriteKernel(context.Context, KernelConfig) error
}

type kernelOwnershipAdapter interface {
	checkKernelOwnership(KernelConfig) error
}

var congestionName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

var kernelParameters = []KernelParameter{
	{"net.core.somaxconn", "namespace", "integer", 0, 2147483647, 1, "Listen backlog ceiling; applications must also request a suitable backlog.", "4096"},
	{"net.ipv4.tcp_max_syn_backlog", "namespace", "integer", 0, 2147483647, 1, "Remembered half-open TCP requests; larger queues consume memory.", "4096"},
	{"net.ipv4.tcp_syncookies", "namespace", "integer", 0, 2, 1, "SYN cookie mode; not a substitute for capacity planning.", "1"},
	{"net.ipv4.tcp_sack", "namespace", "integer", 0, 1, 1, "Selective acknowledgments.", "1"},
	{"net.ipv4.tcp_window_scaling", "namespace", "integer", 0, 1, 1, "TCP window scaling for new connections.", "1"},
	{"net.ipv4.tcp_timestamps", "namespace", "integer", 0, 2, 1, "TCP timestamps and randomized offset mode.", "1"},
	{"net.ipv4.tcp_moderate_rcvbuf", "namespace", "integer", 0, 1, 1, "TCP receive-buffer autotuning.", "1"},
	{"net.ipv4.tcp_mtu_probing", "namespace", "integer", 0, 2, 1, "Path-MTU black-hole probing policy.", "0"},
	{"net.ipv4.tcp_slow_start_after_idle", "namespace", "integer", 0, 1, 1, "Reduce congestion window after idle; disabling can increase bursts.", "1"},
	{"net.ipv4.tcp_autocorking", "namespace", "integer", 0, 1, 1, "Automatic small-write coalescing.", "1"},
	{"net.ipv4.tcp_no_metrics_save", "namespace", "integer", 0, 1, 1, "Disable saving TCP metrics between connections.", "0"},
	{"net.ipv4.tcp_rmem", "namespace", "vector", 1, 2147483647, 3, "Minimum, initial, and maximum TCP receive bytes; limits are per socket, not reservations.", "4096 131072 6291456"},
	{"net.ipv4.tcp_wmem", "namespace", "vector", 1, 2147483647, 3, "Minimum, initial, and maximum TCP send bytes; budget for concurrent sockets.", "4096 16384 4194304"},
	{"net.ipv4.ip_local_port_range", "namespace", "vector", 1, 65535, 2, "Inclusive ephemeral port range; reserved ports and application bindings still apply.", "32768 60999"},
	{"net.ipv4.tcp_congestion_control", "namespace", "algorithm", 0, 0, 0, "Default for new TCP sockets; only already available algorithms are accepted.", "cubic"},
	{"net.core.rmem_max", "host", "integer", 1, 2147483647, 1, "Host-global receive socket-buffer ceiling; affects other applications/namespaces.", "212992"},
	{"net.core.wmem_max", "host", "integer", 1, 2147483647, 1, "Host-global send socket-buffer ceiling.", "212992"},
	{"net.core.rmem_default", "host", "integer", 1, 2147483647, 1, "Host-global default receive socket-buffer size.", "212992"},
	{"net.core.wmem_default", "host", "integer", 1, 2147483647, 1, "Host-global default send socket-buffer size.", "212992"},
	{"net.core.netdev_max_backlog", "host", "integer", 0, 2147483647, 1, "Input processing backlog; larger queues may increase latency and memory use.", "1000"},
	{"net.core.netdev_budget", "host", "integer", 1, 2147483647, 1, "Packets per network softirq polling cycle; competes with other CPU work.", "300"},
	{"net.core.netdev_budget_usecs", "host", "integer", 0, 2147483647, 1, "Network polling time budget in microseconds; higher is not universally faster.", "2000"},
}

func KernelCatalog() []KernelParameter {
	result := slices.Clone(kernelParameters)
	slices.SortFunc(result, func(a, b KernelParameter) int { return strings.Compare(a.Scope+"/"+a.Name, b.Scope+"/"+b.Name) })
	return result
}

func kernelParameter(name, scope string) (KernelParameter, bool) {
	for _, p := range kernelParameters {
		if p.Name == name && p.Scope == scope {
			return p, true
		}
	}
	return KernelParameter{}, false
}

func (c *KernelConfig) Normalize() {
	if c.Namespace == nil {
		c.Namespace = map[string]string{}
	}
	if c.Host == nil {
		c.Host = map[string]string{}
	}
}

func (c KernelConfig) Empty() bool { return len(c.Namespace) == 0 && len(c.Host) == 0 }

func (c KernelConfig) Validate() error {
	for scope, values := range map[string]map[string]string{"namespace": c.Namespace, "host": c.Host} {
		for name, value := range values {
			p, ok := kernelParameter(name, scope)
			if !ok {
				return fmt.Errorf("unsupported kernel tunable %q in scope %s", name, scope)
			}
			if err := validateKernelValue(p, value); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return nil
}

func validateKernelValue(p KernelParameter, value string) error {
	if p.Kind == "algorithm" {
		if !congestionName.MatchString(value) {
			return fmt.Errorf("invalid congestion algorithm name")
		}
		return nil
	}
	fields := strings.Split(value, " ")
	if len(fields) != p.Count {
		return fmt.Errorf("expected %d canonical integer value(s)", p.Count)
	}
	var previous int64
	for i, field := range fields {
		n, err := strconv.ParseInt(field, 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != field || n < p.Min || n > p.Max {
			return fmt.Errorf("expected integer(s) in %d..%d without leading zeros or extra whitespace", p.Min, p.Max)
		}
		if p.Kind == "vector" && i > 0 && n < previous {
			return fmt.Errorf("vector values must be nondecreasing")
		}
		previous = n
	}
	if p.Count == 2 && fields[0] == fields[1] {
		return fmt.Errorf("port range must contain at least two ports")
	}
	return nil
}

func kernelUnion(a, b KernelConfig) KernelConfig {
	result := Clone(a)
	result.Normalize()
	for k, v := range b.Namespace {
		result.Namespace[k] = v
	}
	for k, v := range b.Host {
		result.Host[k] = v
	}
	return result
}

func kernelValues(keys, values KernelConfig) (KernelConfig, error) {
	result := KernelConfig{}
	result.Normalize()
	for scope, requested := range map[string]map[string]string{"namespace": keys.Namespace, "host": keys.Host} {
		source, target := values.Namespace, result.Namespace
		if scope == "host" {
			source, target = values.Host, result.Host
		}
		for name := range requested {
			value, ok := source[name]
			if !ok {
				return KernelConfig{}, fmt.Errorf("missing captured kernel value %s/%s", scope, name)
			}
			target[name] = value
		}
	}
	return result, nil
}

func kernelEqual(a, b KernelConfig) bool {
	a.Normalize()
	b.Normalize()
	return reflect.DeepEqual(a, b)
}

func (e *Engine) captureKernel(ctx context.Context, candidate Config) (*KernelConfig, *KernelConfig, error) {
	keys := kernelUnion(e.state.Desired.Kernel, candidate.Kernel)
	if keys.Empty() {
		return nil, nil, nil
	}
	adapter, ok := e.adapter.(KernelAdapter)
	if !ok {
		return nil, nil, fmt.Errorf("%w: adapter does not support kernel tunables", ErrValidation)
	}
	before, err := adapter.ReadKernel(ctx, keys)
	if err != nil {
		return nil, nil, err
	}
	if err := before.Validate(); err != nil {
		return nil, nil, fmt.Errorf("capture original kernel values: %w", err)
	}
	before, err = kernelValues(keys, before)
	if err != nil {
		return nil, nil, err
	}
	previous, err := kernelValues(e.state.Desired.Kernel, before)
	if err != nil {
		return nil, nil, err
	}
	if !kernelEqual(previous, e.state.Desired.Kernel) {
		return nil, nil, fmt.Errorf("%w: kernel values changed during capture", ErrConflict)
	}
	baseline := kernelUnion(before, e.state.KernelBaseline)
	after, err := kernelValues(keys, baseline)
	if err != nil {
		return nil, nil, err
	}
	after = kernelUnion(after, candidate.Kernel)
	return &before, &after, nil
}

func (e *Engine) writeKernel(ctx context.Context, values *KernelConfig) error {
	if values == nil || values.Empty() {
		return nil
	}
	adapter, ok := e.adapter.(KernelAdapter)
	if !ok {
		return fmt.Errorf("adapter does not support kernel tunable recovery")
	}
	return adapter.WriteKernel(ctx, *values)
}

func (e *Engine) verifyKernel(ctx context.Context, values *KernelConfig) error {
	if values == nil || values.Empty() {
		return nil
	}
	adapter, ok := e.adapter.(KernelAdapter)
	if !ok {
		return fmt.Errorf("adapter does not support kernel tunable verification")
	}
	actual, err := adapter.ReadKernel(ctx, *values)
	if err != nil {
		return err
	}
	if !kernelEqual(actual, *values) {
		return fmt.Errorf("%w: kernel tunable verification mismatch", ErrConflict)
	}
	return nil
}

type KernelView struct {
	Desired    KernelConfig `json:"desired"`
	Configured KernelConfig `json:"configured"`
	Effective  KernelConfig `json:"effective"`
	Observed   KernelConfig `json:"observed"`
	Original   KernelConfig `json:"captured_original"`
	Drift      bool         `json:"drift"`
}

func (e *Engine) KernelView(ctx context.Context) (KernelView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	configured := e.runtimeConfig().Kernel
	effective := configured
	if e.state.Active != "" {
		t := e.state.Transactions[e.state.Active]
		if t.Status == "pending_confirmation" && t.KernelAfter != nil {
			effective = *t.KernelAfter
		} else if t.KernelBefore != nil {
			effective = *t.KernelBefore
		}
	}
	observed := KernelConfig{}
	observed.Normalize()
	if !effective.Empty() {
		adapter, ok := e.adapter.(KernelAdapter)
		if !ok {
			return KernelView{}, fmt.Errorf("adapter does not expose kernel tunables")
		}
		var err error
		observed, err = adapter.ReadKernel(ctx, effective)
		if err != nil {
			return KernelView{}, err
		}
	}
	return Clone(KernelView{Desired: e.state.Desired.Kernel, Configured: configured, Effective: effective, Observed: observed, Original: e.state.KernelBaseline, Drift: !kernelEqual(effective, observed)}), ctx.Err()
}

func validateKernelJournal(state State) error {
	if err := state.KernelBaseline.Validate(); err != nil {
		return fmt.Errorf("invalid kernel baseline: %w", err)
	}
	if _, err := kernelValues(state.Desired.Kernel, state.KernelBaseline); err != nil {
		return err
	}
	for id, t := range state.Transactions {
		if t == nil {
			return fmt.Errorf("nil transaction %s", id)
		}
		keys := kernelUnion(t.Previous.Kernel, t.Candidate.Kernel)
		if keys.Empty() {
			if (t.KernelBefore != nil && !t.KernelBefore.Empty()) || (t.KernelAfter != nil && !t.KernelAfter.Empty()) {
				return fmt.Errorf("unexpected kernel snapshot in %s", id)
			}
			continue
		}
		if t.KernelBefore == nil || t.KernelAfter == nil {
			return fmt.Errorf("missing kernel recovery snapshots in %s", id)
		}
		for _, snapshot := range []*KernelConfig{t.KernelBefore, t.KernelAfter} {
			snapshot.Normalize()
			if err := snapshot.Validate(); err != nil {
				return err
			}
			selected, err := kernelValues(keys, *snapshot)
			if err != nil || !kernelEqual(selected, *snapshot) {
				return fmt.Errorf("incomplete or extra kernel recovery keys in %s", id)
			}
		}
		original, err := kernelValues(keys, state.KernelBaseline)
		if err != nil {
			return err
		}
		if !kernelEqual(*t.KernelAfter, kernelUnion(original, t.Candidate.Kernel)) {
			return fmt.Errorf("inconsistent effective kernel target in %s", id)
		}
		previous, err := kernelValues(t.Previous.Kernel, *t.KernelBefore)
		if err != nil || !kernelEqual(previous, t.Previous.Kernel) {
			return fmt.Errorf("inconsistent previous kernel values in %s", id)
		}
	}
	return nil
}
