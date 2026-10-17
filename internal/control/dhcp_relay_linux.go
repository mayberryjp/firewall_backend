package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gofrs/flock"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type dhcpRelayChild struct {
	bindings []dhcpRelayBinding
	cmd      *exec.Cmd
	done     chan struct{}
	started  time.Time
	exitErr  error
	stopping atomic.Bool
	output   *flowOutput
}

type dhcpRelayManager struct {
	mu       sync.Mutex
	adapter  *linuxAdapter
	binary   string
	root     string
	uid, gid int
	username string
	group    string
	lock     *flock.Flock
	log      *slog.Logger
	child    *dhcpRelayChild
}

func newDHCPRelayManager(a *linuxAdapter, option LinuxOptions) (*dhcpRelayManager, error) {
	if !filepath.IsAbs(option.DHCPRelayRuntimeDirectory) || option.DHCPRelayUID <= 0 || option.DHCPRelayGID <= 0 ||
		uint64(option.DHCPRelayUID) >= uint64(^uint32(0)) || uint64(option.DHCPRelayGID) >= uint64(^uint32(0)) {
		return nil, fmt.Errorf("DHCP relay requires an absolute runtime directory and non-root UID/GID")
	}
	binary, err := validateDaemonBinary(option.DHCPRelayBinary, "DHCP relay dnsmasq")
	if err != nil {
		return nil, err
	}
	account, err := user.LookupId(strconv.Itoa(option.DHCPRelayUID))
	if err != nil {
		return nil, fmt.Errorf("DHCP relay service user: %w", err)
	}
	group, err := user.LookupGroupId(strconv.Itoa(option.DHCPRelayGID))
	if err != nil {
		return nil, fmt.Errorf("DHCP relay service group: %w", err)
	}
	root := option.DHCPRelayRuntimeDirectory
	if err := os.MkdirAll(root, 0711); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0011 != 0011 {
		return nil, fmt.Errorf("DHCP relay runtime directory must be root-owned, non-symlink, non-writable by group/others, and traversable")
	}
	lock := flock.New(filepath.Join(root, "runtime.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("DHCP relay runtime directory is already in use")
	}
	logger := option.Logger
	if logger == nil {
		logger = slog.Default()
	}
	m := &dhcpRelayManager{adapter: a, binary: binary, root: root, uid: option.DHCPRelayUID, gid: option.DHCPRelayGID,
		username: account.Username, group: group.Name, lock: lock, log: logger}
	if err := m.cleanDirectory(); err != nil {
		return nil, errors.Join(err, lock.Unlock())
	}
	return m, nil
}

func (m *dhcpRelayManager) directory() string { return filepath.Join(m.root, "relay") }
func (m *dhcpRelayManager) pidfile() string   { return filepath.Join(m.directory(), "process.pid") }

func (m *dhcpRelayManager) command(args []string, capabilities bool) *exec.Cmd {
	args = append(args, "--user="+m.username, "--group="+m.group)
	cmd := exec.Command(m.binary, args...)
	cmd.Dir, cmd.Env, cmd.WaitDelay = "/", []string{"LANG=C", "LC_ALL=C"}, 2*time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(m.uid), Gid: uint32(m.gid)},
		Pdeathsig:  syscall.SIGKILL,
	}
	if capabilities {
		cmd.SysProcAttr.AmbientCaps = []uintptr{unix.CAP_NET_BIND_SERVICE, unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}
	}
	return cmd
}

func (m *dhcpRelayManager) Preflight(ctx context.Context, interfaces []Interface) error {
	bindings, err := dhcpRelayBindings(interfaces)
	if err != nil || len(bindings) == 0 {
		return errors.Join(err, ctx.Err())
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args := append(dhcpRelayArgs(bindings, m.pidfile()), "--test")
	template := m.command(args, false)
	probe := exec.CommandContext(probeCtx, m.binary, template.Args[1:]...)
	probe.Dir, probe.Env, probe.SysProcAttr, probe.WaitDelay = template.Dir, template.Env, template.SysProcAttr, template.WaitDelay
	output := &flowOutput{limit: 65536}
	probe.Stdout, probe.Stderr = output, output
	if err := probe.Run(); err != nil {
		return fmt.Errorf("DHCP relay dnsmasq configuration check: %w; %s", errors.Join(err, probeCtx.Err()), output.String())
	}
	if output.Truncated() || !strings.Contains(output.String(), "dnsmasq: syntax check OK") {
		return fmt.Errorf("DHCP relay executable did not confirm a dnsmasq syntax check")
	}
	return nil
}

func (m *dhcpRelayManager) snapshot() *dhcpRelayChild {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.child
}

func relayExited(child *dhcpRelayChild) bool {
	select {
	case <-child.done:
		return true
	default:
		return false
	}
}

func (m *dhcpRelayManager) StopChanged(ctx context.Context, interfaces []Interface) error {
	bindings, err := dhcpRelayBindings(interfaces)
	if err != nil {
		return err
	}
	child := m.snapshot()
	if child != nil && (!reflect.DeepEqual(child.bindings, bindings) || relayExited(child)) {
		return m.stop(ctx, child)
	}
	return ctx.Err()
}

func (m *dhcpRelayManager) Reconcile(ctx context.Context, interfaces []Interface) error {
	if err := m.StopChanged(ctx, interfaces); err != nil {
		return err
	}
	bindings, err := dhcpRelayBindings(interfaces)
	if err != nil || len(bindings) == 0 {
		return errors.Join(err, ctx.Err())
	}
	if child := m.snapshot(); child != nil {
		if err := m.ready(child); err == nil {
			return ctx.Err()
		}
		if err := m.stop(ctx, child); err != nil {
			return err
		}
	}
	return m.start(ctx, bindings)
}

func (m *dhcpRelayManager) start(ctx context.Context, bindings []dhcpRelayBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.cleanDirectory(); err != nil {
		return err
	}
	dir := m.directory()
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, m.uid, m.gid); err != nil {
		return errors.Join(err, os.Remove(dir))
	}
	cmd := m.command(dhcpRelayArgs(bindings, m.pidfile()), true)
	output := &flowOutput{logger: m.log, service: "dhcp-relay", name: "relay"}
	cmd.Stdout, cmd.Stderr = output, output
	child := &dhcpRelayChild{bindings: Clone(bindings), cmd: cmd, done: make(chan struct{}), started: time.Now().UTC(), output: output}
	started := make(chan error, 1)
	var once sync.Once
	report := func(err error) { once.Do(func() { started <- err }) }
	// Keep the creating thread pinned until exit so Pdeathsig remains effective.
	go func() {
		err := m.adapter.inNamespace(context.Background(), func() error {
			if err := cmd.Start(); err != nil {
				report(err)
				return err
			}
			report(nil)
			return cmd.Wait()
		})
		report(err)
		child.exitErr = err
		close(child.done)
		if !child.stopping.Load() {
			m.log.Error("DHCP relay exited unexpectedly", "error", err, "output", output.String())
		}
	}()
	if err := <-started; err != nil {
		<-child.done
		return errors.Join(fmt.Errorf("start DHCP relay: %w", err), m.cleanDirectory())
	}
	m.mu.Lock()
	m.child = child
	m.mu.Unlock()
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		last = m.ready(child)
		if last == nil {
			if readyCtx.Err() == nil {
				return nil
			}
			last = readyCtx.Err()
			break
		}
		if relayExited(child) {
			break
		}
		select {
		case <-ticker.C:
			continue
		case <-readyCtx.Done():
			last = errors.Join(last, readyCtx.Err())
		}
		break
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	return errors.Join(fmt.Errorf("DHCP relay readiness: %w; output: %s", last, output.String()), m.stop(stopCtx, child))
}

func (m *dhcpRelayManager) ready(child *dhcpRelayChild) error {
	if relayExited(child) {
		return fmt.Errorf("DHCP relay process exited: %v; output: %s", child.exitErr, child.output.String())
	}
	pid, err := m.readPID()
	if err != nil {
		return err
	}
	if pid != child.cmd.Process.Pid {
		return fmt.Errorf("DHCP relay PID file identity mismatch")
	}
	ns, err := netns.GetFromPid(child.cmd.Process.Pid)
	if err != nil {
		return err
	}
	same := ns.Equal(m.adapter.namespace)
	ns.Close()
	if !same {
		return fmt.Errorf("DHCP relay left its managed namespace")
	}
	return daemonOwnsUDPPort(child.cmd.Process.Pid, 67)
}

func (m *dhcpRelayManager) stop(ctx context.Context, child *dhcpRelayChild) error {
	child.stopping.Store(true)
	if !relayExited(child) {
		if err := child.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
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
				return errors.Join(ctx.Err(), err)
			}
		}
	}
	select {
	case <-child.done:
	case <-time.After(3 * time.Second):
		return fmt.Errorf("DHCP relay did not exit after termination")
	}
	if err := m.cleanDirectory(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.child == child {
		m.child = nil
	}
	m.mu.Unlock()
	return ctx.Err()
}

func (m *dhcpRelayManager) cleanDirectory() error {
	dir := m.directory()
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(m.uid) || info.Mode().Perm() != 0700 {
		return fmt.Errorf("untrusted DHCP relay runtime directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "process.pid" || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected DHCP relay runtime entry %s", entry.Name())
		}
		pid, err := m.readPID()
		if err != nil {
			return err
		}
		err = unix.Kill(pid, 0)
		if err == nil || errors.Is(err, unix.EPERM) {
			return fmt.Errorf("refusing to adopt or unlink a live DHCP relay PID")
		}
		if !errors.Is(err, unix.ESRCH) {
			return err
		}
		if err := os.Remove(m.pidfile()); err != nil {
			return err
		}
	}
	return os.Remove(dir)
}

func (m *dhcpRelayManager) readPID() (int, error) {
	fd, err := unix.Open(m.pidfile(), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), m.pidfile())
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(m.uid) {
		return 0, fmt.Errorf("untrusted DHCP relay PID file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return 0, err
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if parseErr != nil || pid <= 0 || len(data) > 32 {
		return 0, fmt.Errorf("invalid DHCP relay PID file")
	}
	return pid, nil
}

func (m *dhcpRelayManager) Observe(interfaces []Interface) {
	child := m.snapshot()
	actual := map[string]dhcpRelayBinding{}
	var readyErr error
	if child != nil {
		readyErr = m.ready(child)
		for _, binding := range child.bindings {
			actual[binding.Interface] = binding
		}
	}
	for i := range interfaces {
		link := &interfaces[i]
		link.DHCPRelay.Enabled = false
		if binding, exists := actual[link.Name]; exists {
			link.DHCPRelay.Servers = append([]string{}, binding.Servers...)
			link.DHCPRelay.Enabled = readyErr == nil
		}
	}
}

func (m *dhcpRelayManager) Status(interfaces []Interface) []DHCPRelayStatus {
	statuses := dhcpRelayStatuses(interfaces, "not_running", "configured relay is not running")
	child := m.snapshot()
	if child == nil {
		return statuses
	}
	readyErr := m.ready(child)
	for _, binding := range child.bindings {
		status := DHCPRelayStatus{Interface: binding.Interface, State: "running", PID: child.cmd.Process.Pid, StartedAt: &child.started}
		if readyErr != nil {
			status.State, status.Error = "unhealthy", readyErr.Error()
			if relayExited(child) {
				status.State = "exited"
			}
		}
		found := false
		for i := range statuses {
			if statuses[i].Interface == binding.Interface {
				statuses[i], found = status, true
				break
			}
		}
		if !found {
			statuses = append(statuses, status)
		}
	}
	return statuses
}

func (m *dhcpRelayManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	if child := m.snapshot(); child != nil {
		err = m.stop(ctx, child)
	}
	return errors.Join(err, m.lock.Unlock())
}
