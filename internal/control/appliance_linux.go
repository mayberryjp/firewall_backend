package control

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type applianceSpec struct {
	name, binary, text, database string
	managed                      bool
}

type applianceChild struct {
	spec            applianceSpec
	cmd             *exec.Cmd
	done            chan struct{}
	exitErr         error
	started         time.Time
	output          *flowOutput
	stopping        atomic.Bool
	logInode        uint64
	inventoryMu     sync.Mutex
	inventoryErr    error
	inventoryCancel context.CancelFunc
	inventoryDone   chan struct{}
}

type applianceManager struct {
	mu       sync.Mutex
	adapter  *linuxAdapter
	option   LinuxOptions
	host     netns.NsHandle
	lock     *os.File
	children map[string]*applianceChild
	log      *slog.Logger
}

func privateServiceDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
		strings.ContainsAny(path, " \t\r\n\x00\"\\") {
		return fmt.Errorf("service directories must be clean absolute paths without whitespace or quoting")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("service directory %s must be a root-owned non-symlink directory with mode 0700", path)
	}
	return nil
}

func newApplianceManager(a *linuxAdapter, option LinuxOptions) (*applianceManager, error) {
	if !option.AllowHostServices || os.Geteuid() != 0 {
		return nil, fmt.Errorf("appliance daemons require root and explicit -allow-host-services")
	}
	for _, directory := range []string{option.ServicesRuntimeDirectory, option.ServicesStateDirectory} {
		if err := privateServiceDirectory(directory); err != nil {
			return nil, err
		}
	}
	if option.ServicesStateDirectory == option.ServicesRuntimeDirectory ||
		strings.HasPrefix(option.ServicesStateDirectory, option.ServicesRuntimeDirectory+"/") ||
		strings.HasPrefix(option.ServicesRuntimeDirectory, option.ServicesStateDirectory+"/") {
		return nil, fmt.Errorf("service state and runtime directories must be separate, not nested")
	}
	if (option.VNStatBinary == "") != (option.VNStatClientBinary == "") {
		return nil, fmt.Errorf("vnstat supervision requires both vnstatd and vnstat executable paths")
	}
	for _, binary := range []*string{&option.NTPBinary, &option.SyslogBinary, &option.VNStatBinary, &option.VNStatClientBinary} {
		if *binary != "" {
			resolved, err := validateDaemonBinary(*binary, "appliance service")
			if err != nil {
				return nil, err
			}
			*binary = resolved
		}
	}
	fd, err := unix.Open("/run/netcontrol-appliance-services.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "appliance lock")
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err == nil && (st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0) {
		err = fmt.Errorf("untrusted host appliance lock")
	}
	if err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("exclusive host appliance lock: %w", err), lock.Close())
	}
	host, err := netns.GetFromPid(1)
	if err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	logger := option.Logger
	if logger == nil {
		logger = slog.Default()
	}
	m := &applianceManager{adapter: a, option: option, host: host, lock: lock,
		children: map[string]*applianceChild{}, log: logger}
	for _, name := range []string{"ntp", "syslog", "vnstat-host", "vnstat-managed"} {
		if err := m.clearMarker(name); err != nil {
			return nil, errors.Join(err, host.Close(), lock.Close())
		}
	}
	return m, nil
}

func (m *applianceManager) configPath(name string) string {
	return filepath.Join(m.option.ServicesRuntimeDirectory, name+".conf")
}

func (m *applianceManager) marker(name string) string {
	return filepath.Join(m.option.ServicesRuntimeDirectory, name+".supervisor.pid")
}

func (m *applianceManager) clearMarker(name string) error {
	data, err := os.ReadFile(m.marker(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("invalid service ownership marker %s", name)
	}
	err = unix.Kill(pid, 0)
	if err == nil || errors.Is(err, unix.EPERM) {
		return fmt.Errorf("refusing to adopt or remove live service marker %s (PID %d)", name, pid)
	}
	if !errors.Is(err, unix.ESRCH) {
		return err
	}
	return os.Remove(m.marker(name))
}

func (m *applianceManager) specs(c Config) []applianceSpec {
	var result []applianceSpec
	scopeHash := fmt.Sprintf("%x", sha256.Sum256([]byte(m.adapter.scope)))
	for _, s := range []struct {
		name, binary string
		enabled      bool
		managed      bool
	}{
		{"ntp", m.option.NTPBinary, c.NTP.Enabled, false},
		{"syslog", m.option.SyslogBinary, c.Syslog.Enabled, false},
		{"vnstat-host", m.option.VNStatBinary, c.VNStat.Enabled, false},
		{"vnstat-managed", m.option.VNStatBinary, c.VNStat.Enabled, true},
	} {
		if !s.enabled {
			continue
		}
		data := filepath.Join(m.option.ServicesStateDirectory, s.name)
		if s.managed {
			data += "-" + scopeHash
		}
		result = append(result, applianceSpec{name: s.name, binary: s.binary, database: data, managed: s.managed,
			text: applianceConfigurationText(s.name, m.option.ServicesRuntimeDirectory, data, m.option.BackendLogFile, m.option.SyslogCAFile, c)})
	}
	return result
}

func requireServiceCapability(capability int) error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	if data[capability/32].Effective&(uint32(1)<<uint(capability%32)) == 0 {
		return fmt.Errorf("missing host service capability %d", capability)
	}
	return nil
}

func (m *applianceManager) checkConflicts(c Config) error {
	if c.NTP.Enabled {
		if err := requireServiceCapability(unix.CAP_SYS_TIME); err != nil {
			return err
		}
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return err
		}
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			if own := m.children["ntp"]; own != nil && own.cmd.Process.Pid == pid && !applianceExited(own) {
				continue
			}
			data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			switch strings.TrimSpace(string(data)) {
			case "chronyd", "ntpd", "systemd-timesyn", "phc2sys":
				return fmt.Errorf("another clock service is present at PID %d; stop it explicitly before enabling NTP", pid)
			}
		}
	}
	if c.Syslog.Enabled {
		if err := requireServiceCapability(unix.CAP_SYSLOG); err != nil {
			return err
		}
		info, err := os.Lstat("/dev/log")
		if err == nil {
			own := m.children["syslog"]
			stat, ok := info.Sys().(*syscall.Stat_t)
			if own == nil || !ok || own.logInode == 0 || own.logInode != stat.Ino || info.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("/dev/log already exists; explicitly stop the existing system logger and resolve its socket before enabling syslog")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !filepath.IsAbs(m.option.BackendLogFile) {
			return fmt.Errorf("backend log source must be an absolute path")
		}
		info, err = os.Lstat(m.option.BackendLogFile)
		if err != nil {
			return fmt.Errorf("backend log source: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("backend log source must be a root-owned non-symlink regular file, not writable by group/others")
		}
		for _, server := range c.Syslog.Servers {
			if server.Transport == "tls" {
				if !filepath.IsAbs(m.option.SyslogCAFile) {
					return fmt.Errorf("syslog CA bundle must be an absolute path")
				}
				if _, err := os.Stat(m.option.SyslogCAFile); err != nil {
					return fmt.Errorf("syslog CA bundle: %w", err)
				}
			}
		}
	}
	return nil
}

func (m *applianceManager) Preflight(ctx context.Context, c Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkConflicts(c); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	for _, spec := range m.specs(c) {
		if spec.binary == "" {
			return fmt.Errorf("%w: %s binary is not configured", ErrValidation, spec.name)
		}
		probe, err := os.MkdirTemp(m.option.ServicesRuntimeDirectory, "check-")
		if err != nil {
			return err
		}
		err = m.checkConfiguration(ctx, spec, c, probe)
		cleanupErr := os.RemoveAll(probe)
		if err != nil || cleanupErr != nil {
			return errors.Join(err, cleanupErr)
		}
	}
	return ctx.Err()
}

func (m *applianceManager) checkConfiguration(ctx context.Context, spec applianceSpec, c Config, probe string) error {
	text := applianceConfigurationText(spec.name, probe, probe, m.option.BackendLogFile, m.option.SyslogCAFile, c)
	file := filepath.Join(probe, "check.conf")
	if err := os.WriteFile(file, []byte(text), 0600); err != nil {
		return err
	}
	args := []string{"--config", file, "--initdb", "--noadd"}
	if spec.name == "ntp" {
		args = []string{"-p", "-f", file}
	} else if spec.name == "syslog" {
		args = []string{"--syntax-only", "--cfgfile", file}
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, spec.binary, args...)
	cmd.Env, cmd.Dir, cmd.WaitDelay = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}, "/", time.Second
	output := &flowOutput{limit: 65536}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s configuration check: %w; %s", spec.name, errors.Join(err, checkCtx.Err()), output.String())
	}
	return nil
}

func applianceExited(child *applianceChild) bool {
	select {
	case <-child.done:
		return true
	default:
		return false
	}
}

func (m *applianceManager) StopChanged(ctx context.Context, c Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopChanged(ctx, m.specs(c))
}

func (m *applianceManager) stopChanged(ctx context.Context, specs []applianceSpec) error {
	wanted := map[string]applianceSpec{}
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return err
		}
		wanted[spec.name] = spec
	}
	for name, child := range m.children {
		if desired, exists := wanted[name]; !exists || desired != child.spec || applianceExited(child) {
			if err := m.stop(ctx, child); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (m *applianceManager) Reconcile(ctx context.Context, c Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	specs := m.specs(c)
	if err := m.stopChanged(ctx, specs); err != nil {
		return err
	}
	for _, spec := range specs {
		if child := m.children[spec.name]; child != nil {
			if err := m.ready(child); err == nil {
				continue
			}
			if err := m.stop(ctx, child); err != nil {
				return err
			}
		}
		if err := m.start(ctx, spec); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (m *applianceManager) start(ctx context.Context, spec applianceSpec) error {
	if spec.binary == "" {
		return fmt.Errorf("%s integration is not configured", spec.name)
	}
	if err := privateServiceDirectory(spec.database); err != nil {
		return err
	}
	config := m.configPath(spec.name)
	if err := os.WriteFile(config, []byte(spec.text), 0600); err != nil {
		return err
	}
	args := []string{"--nodaemon", "--config", config, "--alwaysadd", "1", "--startempty", "--noremove"}
	if spec.name == "ntp" {
		args = []string{"-d", "-f", config}
	} else if spec.name == "syslog" {
		args = []string{"--foreground", "--cfgfile", config, "--persist-file", filepath.Join(spec.database, "syslog.persist"),
			"--pidfile", filepath.Join(m.option.ServicesRuntimeDirectory, "syslog.pid"),
			"--control", filepath.Join(m.option.ServicesRuntimeDirectory, "syslog.ctl")}
	} else {
		if err := m.vnstatCommand(ctx, spec.binary, config, "--initdb", "--noadd"); err != nil {
			return err
		}
		if err := m.inventory(ctx, spec); err != nil {
			return err
		}
	}
	cmd := exec.Command(spec.binary, args...)
	cmd.Dir, cmd.Env, cmd.WaitDelay = "/", []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}, time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	child := &applianceChild{spec: spec, cmd: cmd, done: make(chan struct{}), started: time.Now().UTC(),
		output: &flowOutput{logger: m.log, service: "appliance", name: spec.name}}
	cmd.Stdout, cmd.Stderr = child.output, child.output
	target := m.host
	if spec.managed {
		target = m.adapter.namespace
	}
	started := make(chan error, 1)
	var once sync.Once
	report := func(err error) { once.Do(func() { started <- err }) }
	go func() {
		err := m.adapter.runInNamespace(ctx, target, spec.managed, func() error {
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
			m.log.Error("appliance service exited", "service", spec.name, "error", err, "output", child.output.String())
		}
	}()
	if err := <-started; err != nil {
		<-child.done
		return err
	}
	m.children[spec.name] = child
	if err := os.WriteFile(m.marker(spec.name), []byte(strconv.Itoa(cmd.Process.Pid)), 0600); err != nil {
		return errors.Join(err, m.stop(context.Background(), child))
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	var last error
	for {
		if last = m.ready(child); last == nil {
			if strings.HasPrefix(spec.name, "vnstat-") {
				m.startInventory(child)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), m.stop(context.Background(), child))
		case <-child.done:
			return errors.Join(fmt.Errorf("%s exited during startup: %w", spec.name, last), m.stop(context.Background(), child))
		case <-deadline.C:
			return errors.Join(fmt.Errorf("%s readiness: %w; %s", spec.name, last, child.output.String()), m.stop(context.Background(), child))
		case <-tick.C:
		}
	}
}

func (m *applianceManager) ready(child *applianceChild) error {
	if applianceExited(child) {
		return fmt.Errorf("process exited: %v; %s", child.exitErr, child.output.String())
	}
	ns, err := netns.GetFromPid(child.cmd.Process.Pid)
	if err != nil {
		return err
	}
	expected := m.host
	if child.spec.managed {
		expected = m.adapter.namespace
	}
	same := ns.Equal(expected)
	ns.Close()
	if !same {
		return fmt.Errorf("service namespace identity changed")
	}
	switch child.spec.name {
	case "ntp":
		data, err := os.ReadFile(filepath.Join(m.option.ServicesRuntimeDirectory, "chrony.pid"))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(data)) != strconv.Itoa(child.cmd.Process.Pid) {
			return fmt.Errorf("chronyd PID identity mismatch")
		}
	case "syslog":
		if err := daemonOwnsUnixSocket(child.cmd.Process.Pid, "/dev/log"); err != nil {
			return err
		}
		info, err := os.Lstat("/dev/log")
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("/dev/log is not a system logging socket")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("system logging socket identity unavailable")
		}
		if child.logInode != 0 && child.logInode != stat.Ino {
			return fmt.Errorf("system logging socket was replaced")
		}
		child.logInode = stat.Ino
	default:
		file, err := os.Open(filepath.Join(child.spec.database, "vnstat.db"))
		if err != nil {
			return err
		}
		defer file.Close()
		header := make([]byte, 16)
		if _, err := io.ReadFull(file, header); err != nil {
			return err
		}
		if string(header) != "SQLite format 3\x00" {
			return fmt.Errorf("vnstat database is not initialized SQLite")
		}
		child.inventoryMu.Lock()
		inventoryErr := child.inventoryErr
		child.inventoryMu.Unlock()
		if inventoryErr != nil {
			return fmt.Errorf("interface inventory: %w", inventoryErr)
		}
	}
	return nil
}

func (m *applianceManager) stop(ctx context.Context, child *applianceChild) error {
	child.stopping.Store(true)
	if child.inventoryCancel != nil {
		child.inventoryCancel()
		select {
		case <-child.inventoryDone:
		case <-time.After(6 * time.Second):
			return fmt.Errorf("vnstat inventory did not terminate")
		}
	}
	if !applianceExited(child) {
		if err := child.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-child.done:
		case <-timer.C:
			m.log.Error("forcing appliance service termination; unsaved data may be lost", "service", child.spec.name)
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
		return fmt.Errorf("%s failed to terminate", child.spec.name)
	}
	if child.spec.name == "syslog" {
		info, err := os.Lstat("/dev/log")
		if err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); !ok || child.logInode == 0 || stat.Ino != child.logInode || info.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("refusing to remove replaced system logging socket")
			}
			if err := os.Remove("/dev/log"); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := m.clearMarker(child.spec.name); err != nil {
		return err
	}
	delete(m.children, child.spec.name)
	return ctx.Err()
}

func (m *applianceManager) Status(c Config) []ApplianceServiceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := applianceStatuses(c, "not_running", "service is not running with expected settings")
	specs := m.specs(c)
	for i := range result {
		for _, spec := range specs {
			child := m.children[spec.name]
			if result[i].Name != spec.name || child == nil || spec != child.spec {
				continue
			}
			result[i].State, result[i].Error, result[i].PID = "running", "", child.cmd.Process.Pid
			result[i].StartedAt = &child.started
			if spec.name == "vnstat-host" || spec.name == "vnstat-managed" {
				result[i].DatabaseDirectory = spec.database
			}
			if err := m.ready(child); err != nil {
				result[i].State, result[i].Error = "unhealthy", err.Error()
				if applianceExited(child) {
					result[i].State = "exited"
				}
			}
		}
	}
	return result
}

func (m *applianceManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var result error
	for _, child := range m.children {
		result = errors.Join(result, m.stop(ctx, child))
	}
	if len(m.children) != 0 {
		return result
	}
	return errors.Join(result, m.host.Close(), m.lock.Close())
}

func (a *linuxAdapter) preflightAppliance(ctx context.Context, c Config) error {
	if a.appliance != nil {
		return a.appliance.Preflight(ctx, c)
	}
	if c.NTP.Enabled || c.Syslog.Enabled || c.VNStat.Enabled {
		return fmt.Errorf("%w: host service integration is not configured by the operator", ErrValidation)
	}
	return ctx.Err()
}

func (m *applianceManager) vnstatCommand(ctx context.Context, binary, config string, args ...string) error {
	_, err := m.vnstatOutput(ctx, binary, config, args...)
	return err
}

func (m *applianceManager) vnstatOutput(ctx context.Context, binary, config string, args ...string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args = append([]string{"--config", config}, args...)
	cmd := exec.CommandContext(probeCtx, binary, args...)
	cmd.Env, cmd.Dir, cmd.WaitDelay = []string{"LANG=C", "LC_ALL=C"}, "/", time.Second
	output := &flowOutput{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vnstat command: %w; %s", errors.Join(err, probeCtx.Err()), output.String())
	}
	if output.Truncated() {
		return "", fmt.Errorf("vnstat interface inventory exceeded 1 MiB")
	}
	return output.String(), nil
}

func (m *applianceManager) inventory(ctx context.Context, spec applianceSpec) error {
	target := m.host
	if spec.managed {
		target = m.adapter.namespace
	}
	batchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return m.adapter.runInNamespace(batchCtx, target, spec.managed, func() error {
		config := m.configPath(spec.name)
		names, err := m.vnstatOutput(batchCtx, m.option.VNStatClientBinary, config, "--dbiflist", "1")
		if err != nil {
			return err
		}
		known := map[string]bool{}
		for _, name := range strings.Fields(names) {
			known[name] = true
		}
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, link := range interfaces {
			if !known[link.Name] {
				if err := m.vnstatCommand(batchCtx, m.option.VNStatClientBinary, config, "--add", "--iface", link.Name); err != nil {
					// vnstatd can discover and insert the same interface concurrently.
					current, lookupErr := m.vnstatOutput(batchCtx, m.option.VNStatClientBinary, config, "--dbiflist", "1")
					found := false
					for _, name := range strings.Fields(current) {
						found = found || name == link.Name
					}
					if lookupErr != nil || !found {
						return fmt.Errorf("track %s in %s: %w", link.Name, spec.name, errors.Join(err, lookupErr))
					}
				}
			}
		}
		return batchCtx.Err()
	})
}

func (m *applianceManager) startInventory(child *applianceChild) {
	ctx, cancel := context.WithCancel(context.Background())
	child.inventoryCancel, child.inventoryDone = cancel, make(chan struct{})
	go func() {
		defer close(child.inventoryDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-child.done:
				return
			case <-ticker.C:
				err := m.inventory(ctx, child.spec)
				if ctx.Err() != nil {
					return
				}
				child.inventoryMu.Lock()
				child.inventoryErr = err
				child.inventoryMu.Unlock()
				if err != nil {
					m.log.Error("vnstat interface inventory failed", "service", child.spec.name, "error", err)
				}
			}
		}
	}()
}
