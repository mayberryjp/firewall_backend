package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/gofrs/flock"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const hostTunablesLockPath = "/run/netcontrol-host-tunables.lock"

func (a *linuxAdapter) initializeHostTunables() error {
	info, err := os.Lstat("/run")
	if err != nil {
		return err
	}
	var parent unix.Stat_t
	if err := unix.Lstat("/run", &parent); err != nil {
		return err
	}
	if !info.IsDir() || parent.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("host tuning requires a trusted root-owned /run directory")
	}
	fd, err := unix.Open(hostTunablesLockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	var lockStat unix.Stat_t
	statErr := unix.Fstat(fd, &lockStat)
	closeErr := unix.Close(fd)
	if err := errors.Join(statErr, closeErr); err != nil {
		return err
	}
	if lockStat.Uid != 0 || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&0022 != 0 {
		return fmt.Errorf("untrusted host tunables lock file")
	}
	lock := flock.New(hostTunablesLockPath)
	locked, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("host tunables are already owned by another manager")
	}
	host, err := netns.GetFromPid(1)
	if err != nil {
		return errors.Join(err, lock.Unlock())
	}
	a.hostNamespace, a.hostTunablesLock = host, lock
	return nil
}

func (a *linuxAdapter) checkKernelOwnership(values KernelConfig) error {
	if len(values.Host) > 0 && a.hostTunablesLock == nil {
		return fmt.Errorf("journal owns host tunables: operator -allow-host-tunables is required for observation and recovery")
	}
	return nil
}

func (a *linuxAdapter) kernelScope(ctx context.Context, scope string, fn func() error) error {
	if scope == "namespace" {
		return a.inNamespace(ctx, fn)
	}
	if a.hostTunablesLock == nil {
		return fmt.Errorf("%w: host-global tunables require operator -allow-host-tunables", ErrValidation)
	}
	return a.runInNamespace(ctx, a.hostNamespace, false, fn)
}

func openKernelFile(name string, write bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if write {
		flags = unix.O_WRONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	path := "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open kernel tunable %s: %w", name, err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.Join(fmt.Errorf("%s is not procfs", name), unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readKernelFile(p KernelParameter) (string, error) {
	f, err := openKernelFile(p.Name, false)
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 257))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return "", err
	}
	if len(data) > 256 {
		return "", fmt.Errorf("oversized kernel value for %s", p.Name)
	}
	value := strings.Join(strings.Fields(string(data)), " ")
	if err := validateKernelValue(p, value); err != nil {
		return "", fmt.Errorf("unsupported observed value for %s: %w", p.Name, err)
	}
	return value, nil
}

func (a *linuxAdapter) ReadKernel(ctx context.Context, keys KernelConfig) (KernelConfig, error) {
	if err := keys.Validate(); err != nil {
		return KernelConfig{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	result := KernelConfig{}
	result.Normalize()
	for _, scope := range []string{"host", "namespace"} {
		requested, target := keys.Namespace, result.Namespace
		if scope == "host" {
			requested, target = keys.Host, result.Host
		}
		if len(requested) == 0 {
			continue
		}
		err := a.kernelScope(ctx, scope, func() error {
			for _, name := range sortedKernelNames(requested) {
				if err := ctx.Err(); err != nil {
					return err
				}
				p, _ := kernelParameter(name, scope)
				value, err := readKernelFile(p)
				if err != nil {
					return err
				}
				target[name] = value
			}
			return nil
		})
		if err != nil {
			return KernelConfig{}, err
		}
	}
	return result, ctx.Err()
}

func sortedKernelNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func kernelAlgorithmAvailable(value string) error {
	f, err := openKernelFile("net.ipv4.tcp_available_congestion_control", false)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 4097))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	if len(data) > 4096 {
		return fmt.Errorf("oversized congestion algorithm inventory")
	}
	if !slices.Contains(strings.Fields(string(data)), value) {
		return fmt.Errorf("%w: congestion algorithm %q is not currently available; load it separately or select an available algorithm", ErrValidation, value)
	}
	return nil
}

func (a *linuxAdapter) preflightKernel(ctx context.Context, values KernelConfig) error {
	if _, err := a.ReadKernel(ctx, values); err != nil {
		return err
	}
	for _, scope := range []string{"host", "namespace"} {
		requested := values.Namespace
		if scope == "host" {
			requested = values.Host
		}
		if len(requested) == 0 {
			continue
		}
		if err := a.kernelScope(ctx, scope, func() error {
			for _, name := range sortedKernelNames(requested) {
				if err := ctx.Err(); err != nil {
					return err
				}
				if name == "net.ipv4.tcp_congestion_control" {
					if err := kernelAlgorithmAvailable(requested[name]); err != nil {
						return err
					}
				}
				f, err := openKernelFile(name, true)
				if err != nil {
					return err
				}
				if err := f.Close(); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func writeKernelFile(p KernelParameter, value string) error {
	current, err := readKernelFile(p)
	if err != nil {
		return err
	}
	if current == value {
		return nil
	}
	if p.Kind == "algorithm" {
		if err := kernelAlgorithmAvailable(value); err != nil {
			return err
		}
	}
	f, err := openKernelFile(p.Name, true)
	if err != nil {
		return err
	}
	payload := []byte(value + "\n")
	n, writeErr := f.Write(payload)
	if n != len(payload) {
		writeErr = errors.Join(writeErr, io.ErrShortWrite)
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return fmt.Errorf("write %s: %w", p.Name, err)
	}
	actual, err := readKernelFile(p)
	if err != nil {
		return err
	}
	if actual != value {
		return fmt.Errorf("kernel rejected/clamped %s: requested %s, observed %s", p.Name, value, actual)
	}
	return nil
}

func (a *linuxAdapter) WriteKernel(ctx context.Context, values KernelConfig) error {
	if err := values.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	var result error
	for _, scope := range []string{"host", "namespace"} {
		requested := values.Namespace
		if scope == "host" {
			requested = values.Host
		}
		if len(requested) == 0 {
			continue
		}
		err := a.kernelScope(ctx, scope, func() error {
			var failures error
			for _, name := range sortedKernelNames(requested) {
				if err := ctx.Err(); err != nil {
					return errors.Join(failures, err)
				}
				p, _ := kernelParameter(name, scope)
				failures = errors.Join(failures, writeKernelFile(p, requested[name]))
			}
			return failures
		})
		result = errors.Join(result, err)
	}
	return errors.Join(result, ctx.Err())
}
