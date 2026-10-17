package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gofrs/flock"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type softflowdChild struct {
	config   SoftflowdConfig
	cmd      *exec.Cmd
	dir      string
	started  time.Time
	done     chan struct{}
	exitErr  error
	stopping atomic.Bool
	output   *flowOutput
}

type softflowdManager struct {
	mu       sync.Mutex
	adapter  *linuxAdapter
	binary   string
	root     string
	uid, gid int
	lock     *flock.Flock
	log      *slog.Logger
	help     string
	children map[string]*softflowdChild
}

type flowOutput struct {
	mu        sync.Mutex
	text      string
	limit     int
	truncated bool
	logger    *slog.Logger
	name      string
}

func (o *flowOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.text += string(p)
	limit := o.limit
	if limit == 0 {
		limit = 8192
	}
	if len(o.text) > limit {
		o.text = o.text[len(o.text)-limit:]
		o.truncated = true
	}
	if o.logger != nil {
		o.logger.Info("softflowd output", "instance", o.name, "message", string(p[:min(len(p), 4096)]), "truncated", len(p) > 4096)
	}
	return len(p), nil
}

func (o *flowOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.text
}

func (o *flowOutput) Truncated() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.truncated
}

func newSoftflowdManager(a *linuxAdapter, option LinuxOptions) (*softflowdManager, error) {
	if !filepath.IsAbs(option.SoftflowdBinary) || !filepath.IsAbs(option.RuntimeDirectory) ||
		option.SoftflowdUID <= 0 || option.SoftflowdGID <= 0 || uint64(option.SoftflowdUID) > uint64(^uint32(0)-1) || uint64(option.SoftflowdGID) > uint64(^uint32(0)-1) {
		return nil, fmt.Errorf("softflowd requires absolute operator-supplied binary/runtime paths and non-root UID/GID")
	}
	binary, err := filepath.EvalSymlinks(option.SoftflowdBinary)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(binary)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 || stat.Uid != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, fmt.Errorf("softflowd binary must be a root-owned executable without set-ID bits and not writable by group/others")
	}
	capabilityBytes, err := unix.Getxattr(binary, "security.capability", nil)
	if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return nil, fmt.Errorf("inspect softflowd file capabilities: %w", err)
	}
	if capabilityBytes > 0 {
		return nil, fmt.Errorf("softflowd binary must not carry file capabilities; capture capabilities are supplied to the child")
	}
	if err := os.MkdirAll(option.RuntimeDirectory, 0711); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(option.RuntimeDirectory)
	if err != nil {
		return nil, err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || !rootInfo.IsDir() || rootStat.Uid != 0 || rootInfo.Mode().Perm()&0022 != 0 || rootInfo.Mode().Perm()&0011 != 0011 {
		return nil, fmt.Errorf("softflowd runtime directory must be root-owned, non-symlink, non-writable by group/others, and traversable (mode 0711)")
	}
	lock := flock.New(filepath.Join(option.RuntimeDirectory, "runtime.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("softflowd runtime directory is already in use")
	}
	logger := option.Logger
	if logger == nil {
		logger = slog.Default()
	}
	m := &softflowdManager{adapter: a, binary: binary, root: option.RuntimeDirectory, uid: option.SoftflowdUID, gid: option.SoftflowdGID,
		lock: lock, log: logger, children: map[string]*softflowdChild{}}
	entries, err := os.ReadDir(m.root)
	if err == nil {
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "instance-") {
				continue
			}
			name := strings.TrimPrefix(entry.Name(), "instance-")
			if !serviceNamePattern.MatchString(name) {
				err = fmt.Errorf("unrecognized softflowd runtime entry %s", entry.Name())
				break
			}
			if err = m.cleanDirectory(filepath.Join(m.root, entry.Name())); err != nil {
				break
			}
		}
	}
	if err != nil {
		return nil, errors.Join(err, lock.Unlock())
	}
	return m, nil
}

func (m *softflowdManager) command(args []string, capture, promiscuous bool) *exec.Cmd {
	cmd := exec.Command(m.binary, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(m.uid), Gid: uint32(m.gid)},
		Pdeathsig:  syscall.SIGKILL,
	}
	if capture {
		cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_RAW}
		if promiscuous {
			cmd.SysProcAttr.AmbientCaps = append(cmd.SysProcAttr.AmbientCaps, unix.CAP_NET_ADMIN)
		}
	}
	return cmd
}

func (m *softflowdManager) Preflight(ctx context.Context, configs []SoftflowdConfig) error {
	enabled := false
	for _, s := range configs {
		if !s.Enabled {
			continue
		}
		enabled = true
		if len(filepath.Join(m.root, "instance-"+s.Name, "control.sock")) > 107 {
			return fmt.Errorf("%w: softflowd control socket path exceeds Linux limit", ErrValidation)
		}
	}
	if !enabled {
		return ctx.Err()
	}
	m.mu.Lock()
	help := m.help
	m.mu.Unlock()
	if help == "" {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cmd := m.command([]string{"-h"}, false, false)
		output := &flowOutput{limit: 65536}
		cmd.Stdout, cmd.Stderr = output, output
		// CommandContext's cancellation wiring is needed for even a misbehaving
		// operator-installed binary, without invoking a shell or a timeout tool.
		probe := exec.CommandContext(probeCtx, m.binary, "-h")
		probe.Dir, probe.Env, probe.SysProcAttr, probe.WaitDelay = cmd.Dir, cmd.Env, cmd.SysProcAttr, cmd.WaitDelay
		probe.Stdout, probe.Stderr = output, output
		err := probe.Run()
		if probeCtx.Err() != nil {
			return fmt.Errorf("softflowd capability probe: %w", probeCtx.Err())
		}
		var exit *exec.ExitError
		if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
			return fmt.Errorf("softflowd capability probe: %w", err)
		}
		if output.Truncated() {
			return fmt.Errorf("softflowd capability probe exceeded 65536 output bytes")
		}
		help = output.String()
		if !strings.Contains(strings.ToLower(help), "softflowd") {
			return fmt.Errorf("configured executable did not identify itself as softflowd")
		}
		for _, flag := range []string{"d", "i", "n", "v", "P", "s", "m", "C", "c", "p", "N", "t"} {
			if !regexp.MustCompile(`(?m)-` + flag + `(?:[ ,\t]|$)`).MatchString(help) {
				return fmt.Errorf("installed softflowd does not advertise required -%s option", flag)
			}
		}
		m.mu.Lock()
		m.help = help
		m.mu.Unlock()
	}
	for _, s := range configs {
		if s.Enabled && !regexp.MustCompile(fmt.Sprintf(`(?m)-v[^\n]*\b%d\b`, s.ExportVersion)).MatchString(help) {
			return fmt.Errorf("%w: installed softflowd does not advertise export version %d", ErrValidation, s.ExportVersion)
		}
	}
	return nil
}

func (m *softflowdManager) snapshot() map[string]*softflowdChild {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]*softflowdChild, len(m.children))
	for name, child := range m.children {
		result[name] = child
	}
	return result
}

func exited(child *softflowdChild) bool {
	select {
	case <-child.done:
		return true
	default:
		return false
	}
}

func (m *softflowdManager) StopChanged(ctx context.Context, configs []SoftflowdConfig) error {
	wanted := map[string]SoftflowdConfig{}
	for _, s := range configs {
		wanted[s.Name] = s
	}
	for name, child := range m.snapshot() {
		next, exists := wanted[name]
		if !exists || !next.Enabled || !reflect.DeepEqual(next, child.config) || exited(child) {
			if err := m.stop(ctx, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *softflowdManager) Reconcile(ctx context.Context, configs []SoftflowdConfig) error {
	if err := m.StopChanged(ctx, configs); err != nil {
		return err
	}
	for _, s := range configs {
		if !s.Enabled {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		child := m.snapshot()[s.Name]
		if child != nil {
			if err := m.ready(ctx, child); err == nil {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := m.stop(ctx, child); err != nil {
				return err
			}
		}
		if err := m.start(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func (m *softflowdManager) start(ctx context.Context, config SoftflowdConfig) error {
	dir := filepath.Join(m.root, "instance-"+config.Name)
	if _, err := os.Lstat(dir); err == nil {
		if err := m.cleanDirectory(dir); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, m.uid, m.gid); err != nil {
		return errors.Join(err, os.Remove(dir))
	}
	output := &flowOutput{logger: m.log, name: config.Name}
	cmd := m.command(softflowdArgs(config, filepath.Join(dir, "control.sock"), filepath.Join(dir, "process.pid")), true, config.Promiscuous)
	cmd.Stdout, cmd.Stderr = output, output
	child := &softflowdChild{config: Clone(config), cmd: cmd, dir: dir, done: make(chan struct{}), output: output, started: time.Now().UTC()}
	started := make(chan error, 1)
	var startResult sync.Once
	reportStart := func(err error) { startResult.Do(func() { started <- err }) }
	// The creating OS thread stays pinned until Wait completes. Linux
	// Pdeathsig is tied to that thread, not merely to the Go process.
	go func() {
		err := m.adapter.inNamespace(context.Background(), func() error {
			if err := cmd.Start(); err != nil {
				reportStart(err)
				return err
			}
			reportStart(nil)
			return cmd.Wait()
		})
		reportStart(err)
		child.exitErr = err
		close(child.done)
		if !child.stopping.Load() {
			m.log.Error("softflowd exited unexpectedly", "instance", config.Name, "error", err)
		}
	}()
	if err := <-started; err != nil {
		<-child.done
		return errors.Join(fmt.Errorf("start softflowd %s: %w", config.Name, err), m.cleanDirectory(dir))
	}
	m.mu.Lock()
	m.children[config.Name] = child
	m.mu.Unlock()
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		last = m.ready(readyCtx, child)
		if last == nil {
			return nil
		}
		if exited(child) {
			break
		}
		select {
		case <-readyCtx.Done():
			last = errors.Join(last, readyCtx.Err())
		case <-ticker.C:
			continue
		}
		break
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	return errors.Join(fmt.Errorf("softflowd %s readiness: %w; output: %s", config.Name, last, output.String()), m.stop(stopCtx, child))
}

func (m *softflowdManager) ready(ctx context.Context, child *softflowdChild) error {
	if exited(child) {
		return fmt.Errorf("process exited: %v", child.exitErr)
	}
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "unix", filepath.Join(child.dir, "control.sock"))
	if err != nil {
		return err
	}
	defer conn.Close()
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unexpected control socket type")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if peerErr != nil {
		return peerErr
	}
	if peer.Pid != int32(child.cmd.Process.Pid) || peer.Uid != uint32(m.uid) {
		return fmt.Errorf("control socket process identity mismatch")
	}
	ns, err := netns.GetFromPid(child.cmd.Process.Pid)
	if err != nil {
		return err
	}
	same := ns.Equal(m.adapter.namespace)
	ns.Close()
	if !same {
		return fmt.Errorf("softflowd left its managed network namespace")
	}
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, "statistics\n"); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(conn, 16385))
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > 16384 {
		return fmt.Errorf("invalid or oversized control socket reply")
	}
	return nil
}

func (m *softflowdManager) stop(ctx context.Context, child *softflowdChild) error {
	child.stopping.Store(true)
	if !exited(child) {
		err := child.cmd.Process.Signal(syscall.SIGTERM)
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-child.done:
		case <-timer.C:
			if err := child.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
		case <-ctx.Done():
			if err := child.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return errors.Join(err, ctx.Err())
			}
		}
	}
	select {
	case <-child.done:
	case <-time.After(3 * time.Second):
		return fmt.Errorf("softflowd %s did not exit after termination", child.config.Name)
	}
	if err := m.cleanDirectory(child.dir); err != nil {
		return err
	}
	m.mu.Lock()
	if m.children[child.config.Name] == child {
		delete(m.children, child.config.Name)
	}
	m.mu.Unlock()
	return nil
}

func (m *softflowdManager) cleanDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(m.uid) || info.Mode().Perm() != 0700 {
		return fmt.Errorf("untrusted softflowd instance directory %s", dir)
	}
	control := filepath.Join(dir, "control.sock")
	conn, err := net.DialTimeout("unix", control, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		return fmt.Errorf("refusing to adopt or unlink a live softflowd control socket at %s", control)
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("inspect stale control socket: %w", err)
	}
	for _, name := range []string{"control.sock", "process.pid"} {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if name == "control.sock" && info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("unexpected control path type")
		}
		if name == "process.pid" && !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected PID path type")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return os.Remove(dir)
}

func (m *softflowdManager) Observe(ctx context.Context, hints []SoftflowdConfig) []SoftflowdConfig {
	actual := map[string]SoftflowdConfig{}
	for name, child := range m.snapshot() {
		config := Clone(child.config)
		config.Enabled = m.ready(ctx, child) == nil
		actual[name] = config
	}
	for _, hint := range hints {
		if _, exists := actual[hint.Name]; !exists {
			hint = Clone(hint)
			hint.Enabled = false
			actual[hint.Name] = hint
		}
	}
	result := make([]SoftflowdConfig, 0, len(actual))
	for _, config := range actual {
		result = append(result, config)
	}
	return result
}

func (m *softflowdManager) Status(ctx context.Context, hints []SoftflowdConfig) []SoftflowdStatus {
	statuses := map[string]SoftflowdStatus{}
	for _, hint := range hints {
		status := SoftflowdStatus{Name: hint.Name, State: "disabled"}
		if hint.Enabled {
			status.State, status.Error = "not_running", "configured instance is not running"
		}
		statuses[hint.Name] = status
	}
	for name, child := range m.snapshot() {
		status := SoftflowdStatus{Name: name, State: "running", PID: child.cmd.Process.Pid, StartedAt: &child.started}
		if err := m.ready(ctx, child); err != nil {
			status.State, status.Error = "unhealthy", err.Error()
			if exited(child) {
				status.State = "exited"
			}
		}
		statuses[name] = status
	}
	result := make([]SoftflowdStatus, 0, len(statuses))
	for _, status := range statuses {
		result = append(result, status)
	}
	slices.SortFunc(result, func(a, b SoftflowdStatus) int { return strings.Compare(a.Name, b.Name) })
	return result
}

func (m *softflowdManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var result error
	for _, child := range m.snapshot() {
		result = errors.Join(result, m.stop(ctx, child))
	}
	return errors.Join(result, m.lock.Unlock())
}
